#include <wallet/token.h>
#include <util/strencodings.h>
#include <net.h>
#include <protocol.h>
#include <wallet/wallet.h>
#include <util/message.h>
#include <util/time.h>
#include <key_io.h>
#include <wallet/coincontrol.h>
#include <script/standard.h>
#include <outputtype.h>
#include <util/translation.h>
#include <random.h>
#include <dbwrapper.h>
#include <util/system.h>
#include <chainparams.h>
#include <validation.h>
#include <validationinterface.h>
#include <optional.h>

extern std::unique_ptr<CConnman> g_connman;

static std::unique_ptr<CDBWrapper> g_token_db;

namespace {
class TokenValidationInterface : public CValidationInterface {
public:
    void BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* index) override {
        g_token_ledger.ProcessBlock(*block, index->nHeight);
    }
    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* index) override {
        g_token_ledger.RescanFromHeight(index->nHeight);
    }
};

std::shared_ptr<TokenValidationInterface> g_token_validation;
}

void RegisterTokenValidationInterface()
{
    if (!g_token_validation) {
        g_token_validation = std::make_shared<TokenValidationInterface>();
        RegisterSharedValidationInterface(g_token_validation);
    }
}

void UnregisterTokenValidationInterface()
{
    if (g_token_validation) {
        UnregisterSharedValidationInterface(g_token_validation);
        g_token_validation.reset();
    }
}

bool IsValidTokenId(const std::string& token)
{
    if (token.size() != 59) return false;
    if (token.compare(0, 2, "0x") != 0) return false;
    if (token.substr(56) != "tok") return false;
    for (size_t i = 2; i < 56; ++i) {
        if (HexDigit(token[i]) < 0) return false;
    }
    return true;
}

std::string GenerateTokenId(const std::string& creator, const std::string& name)
{
    int extranonce = 0;

    while (true) {
        CHashWriter hasher(SER_GETHASH, 0);
        hasher << creator << name << extranonce;

        uint256 hash = hasher.GetHash();
        std::string token = "0x" + hash.GetHex().substr(0, 54) + "tok";

        // Ensure token ID is unique in the ledger
        bool exists = false;
        for (const auto& item : g_token_ledger.ListAllTokens()) {
            if (std::get<0>(item) == token) {
                exists = true;
                break;
            }
        }

        if (!exists) return token;

        extranonce++;
    }
}

uint256 TokenOperationHash(const TokenOperation& op)
{
    TokenOperation tmp = op;
    tmp.signature.clear();
    tmp.signer.clear();
    LogPrintf("🔍 TokenOperationHash: %s\n", SerializeHash(tmp).GetHex());
    LogPrintf("🔍 TokenOperationHash tmp: %s\n", BuildTokenMsg(tmp));
    LogPrintf("🔍 TokenOperationHash op: %s\n", BuildTokenMsg(op));

    return SerializeHash(tmp);
}

void BroadcastTokenOp(const TokenOperation& op)
{
    if (!g_connman) return;
    g_connman->ForEachNode([&](CNode* pnode) {
        CNetMsgMaker msgMaker(pnode->GetCommonVersion());
        g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::TOKENTX, op));
    });
}

CAmount TokenLedger::GovernanceBalance() const
{
    LOCK(m_mutex);
    return m_governance_fees;
}
void TokenLedger::RegisterToken(const std::string& token, const std::string& name, const std::string& symbol, uint8_t decimals, const std::string& owner, int64_t height)
{
    m_token_meta[token] = {name, symbol, decimals, owner, height};
}

void TokenLedger::CreateToken(const std::string& wallet, const std::string& token, CAmount amount, const std::string& name, const std::string& symbol, uint8_t decimals, int64_t height)
{
    m_balances[{wallet, token}] += amount;
    m_totalSupply[token] += amount;
    if (m_token_meta.count(token) == 0) {
        RegisterToken(token, name, symbol, decimals, wallet, height);
    }
}

CAmount TokenLedger::Balance(const std::string& wallet, const std::string& token) const
{
    LOCK(m_mutex);
    auto it = m_balances.find({wallet, token});
    if (it == m_balances.end()) return 0;
    return it->second;
}

CAmount TokenLedger::GetBalance(const std::string& wallet, const std::string& token) const
{
    LOCK(m_mutex);
    auto it = m_balances.find({wallet, token});
    if (it == m_balances.end()) return 0;
    return it->second;
}

void TokenLedger::Approve(const std::string& owner, const std::string& spender, const std::string& token, CAmount amount)
{
    LOCK(m_mutex);
    m_allowances[{owner, spender, token}] = amount;
}

void TokenLedger::IncreaseAllowance(const std::string& owner, const std::string& spender, const std::string& token, CAmount amount)
{
    LOCK(m_mutex);
    m_allowances[{owner, spender, token}] += amount;
}

void TokenLedger::DecreaseAllowance(const std::string& owner, const std::string& spender, const std::string& token, CAmount amount)
{
    LOCK(m_mutex);
    auto& val = m_allowances[{owner, spender, token}];
    if (val <= amount) {
        m_allowances.erase({owner, spender, token});
    } else {
        val -= amount;
    }
}

CAmount TokenLedger::Allowance(const std::string& owner, const std::string& spender, const std::string& token) const
{
    LOCK(m_mutex);
    auto it = m_allowances.find({owner, spender, token});
    if (it == m_allowances.end()) return 0;
    return it->second;
}

bool TokenLedger::Transfer(const std::string& from, const std::string& to, const std::string& token, CAmount amount)
{
    LOCK(m_mutex);
    CAmount& from_bal = m_balances[{from, token}];
    if (from_bal < amount) return false;
    from_bal -= amount;
    m_balances[{to, token}] += amount;
    return true;
}

bool TokenLedger::TransferFrom(const std::string& spender, const std::string& from, const std::string& to, const std::string& token, CAmount amount)
{
    LOCK(m_mutex);
    AllowanceKey key{from, spender, token};
    auto it = m_allowances.find(key);
    if (it == m_allowances.end() || it->second < amount) return false;
    CAmount& from_bal = m_balances[{from, token}];
    if (from_bal < amount) return false;
    from_bal -= amount;
    m_balances[{to, token}] += amount;
    it->second -= amount;
    return true;
}

bool TokenLedger::Burn(const std::string& wallet, const std::string& token, CAmount amount)
{
    LOCK(m_mutex);
    auto meta_it = m_token_meta.find(token);
    if (meta_it == m_token_meta.end()) return false;
    CAmount& bal = m_balances[{wallet, token}];
    if (bal < amount) return false;
    bal -= amount;
    m_totalSupply[token] -= amount;
    return true;
}

bool TokenLedger::Mint(const std::string& wallet, const std::string& token, CAmount amount)
{
    LOCK(m_mutex);
    auto meta_it = m_token_meta.find(token);
    if (meta_it == m_token_meta.end()) return false;
    m_balances[{wallet, token}] += amount;
    m_totalSupply[token] += amount;
    return true;
}

bool TokenLedger::TransferOwnership(const std::string& from, const std::string& to, const std::string& token)
{
    LOCK(m_mutex);
    auto it = m_token_meta.find(token);
    if (it == m_token_meta.end() || it->second.operator_wallet != from) return false;
    it->second.operator_wallet = to;
    return true;
}

CAmount TokenLedger::TotalSupply(const std::string& token) const
{
    LOCK(m_mutex);
    auto it = m_totalSupply.find(token);
    if (it == m_totalSupply.end()) return 0;
    return it->second;
}

Optional<TokenMeta> TokenLedger::GetTokenMeta(const std::string& token) const
{
    LOCK(m_mutex);
    auto it = m_token_meta.find(token);
    if (it == m_token_meta.end()) return nullopt;
    return it->second;
}

std::vector<std::tuple<std::string,std::string,std::string>> TokenLedger::ListAllTokens() const
{
    LOCK(m_mutex);
    std::vector<std::tuple<std::string,std::string,std::string>> out;
    for (const auto& kv : m_token_meta) {
        out.emplace_back(kv.first, kv.second.name, kv.second.symbol);
    }
    return out;
}

std::vector<std::tuple<std::string,std::string,std::string>> TokenLedger::ListWalletTokens(const std::string& address) const
{
    LOCK(m_mutex);
    std::set<std::string> tokens;
    for (const auto& kv : m_balances) {
        if (kv.first.first == address && kv.second > 0) {
            tokens.insert(kv.first.second);
        }
    }
    std::vector<std::tuple<std::string,std::string,std::string>> out;
    for (const auto& token : tokens) {
        auto it = m_token_meta.find(token);
        std::string name, symbol;
        if (it != m_token_meta.end()) {
            name = it->second.name;
            symbol = it->second.symbol;
        }
        out.emplace_back(token, name, symbol);
    }
    return out;
}

bool TokenLedger::SendGovernanceFee(const std::string& wallet, CAmount fee)
{
    std::shared_ptr<CWallet> from = GetWallet(wallet);
    if (!from) {
        LogPrintf("❌ Source wallet not found: %s\n", wallet);
        return false;
    }

    LOCK(from->cs_wallet);

    CTxDestination dest = DecodeDestination(m_governance_wallet);
    if (!IsValidDestination(dest)) {
        LogPrintf("❌ Invalid governance wallet address: %s\n", m_governance_wallet);
        return false;
    }

    CRecipient recipient{GetScriptForDestination(dest), fee, /*subtractFeeFromAmount=*/false};
    CCoinControl cc;
    std::vector<CRecipient> vecSend{recipient};
    CAmount nFeeRequired;
    int nChangePosRet = -1;
    bilingual_str err;
    CTransactionRef tx;
    FeeCalculation fee_calc;

    bool created = from->CreateTransaction(vecSend, tx, nFeeRequired, nChangePosRet, err, cc, fee_calc, !from->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    if (!created || !tx) {
        LogPrintf("❌ Failed to create governance fee transaction: %s\n", err.original);
        return false;
    }
    from->CommitTransaction(tx, {}, {});
    LogPrintf("✅ Governance fee transaction committed: %s\n", tx->GetHash().ToString());
    return true;
}

bool TokenLedger::SignTokenOperation(TokenOperation& op, CWallet& wallet, const std::string& walletName, bool witness)
{
    std::string signer = GetSignerAddress(walletName, wallet, witness);
    if (signer.empty()) {
        LogPrintf("❌ SignTokenOperation: No signer address found\n");
        return false;
    }

    op.signer = signer;
    op.timestamp = GetTime();
    LogPrintf("✍️ SignTokenOperation: OP to sign: %s\n", BuildTokenMsg(op));

    CTxDestination dest = DecodeDestination(signer);
    if (!IsValidDestination(dest)) {
        LogPrintf("❌ SignTokenOperation: Invalid destination '%s'\n", signer);
        return false;
    }

    // Sign over all token operation fields to prevent tampering
    std::string message = BuildTokenMsg(op);

    SigningResult err;
    switch (witness) {
    case true:
        if (const WitnessV0KeyHash* wpkh = boost::get<WitnessV0KeyHash>(&dest)) {
            err = wallet.SignMessage(message, PKHash(uint160(*wpkh)), op.signature);
        } else {
            LogPrintf("❌ SignTokenOperation: Signer not witness address\n");
            return false;
        }
        break;
    case false:
        if (const PKHash* pkhash = boost::get<PKHash>(&dest)) {
            err = wallet.SignMessage(message, *pkhash, op.signature);
        } else {
            LogPrintf("❌ SignTokenOperation: Signer not legacy address\n");
            return false;
        }
        break;
    }
    if (err != SigningResult::OK) return false;

    LogPrintf("✅ SignTokenOperation: Signed by %s\n", signer);
    return true;
}

bool TokenLedger::SignTokenOperationWithKey(TokenOperation& op, const std::string& wifKey)
{
    CKey key = DecodeSecret(wifKey);
    if (!key.IsValid()) {
        LogPrintf("❌ SignTokenOperationWithKey: Invalid WIF key\n");
        return false;
    }

    CPubKey pubkey = key.GetPubKey();
    CTxDestination dest;
    // Default to segwit address for WIF signing
    dest = WitnessV0KeyHash(pubkey);
    
    std::string signer = EncodeDestination(dest);
    op.signer = signer;
    op.timestamp = GetTime();
    
    std::string message = BuildTokenMsg(op);
    LogPrintf("✍️ SignTokenOperationWithKey: OP to sign: %s\n", message);

    uint256 hash = MessageHash(message);
    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(hash, vchSig)) {
        LogPrintf("❌ SignTokenOperationWithKey: Signing failed\n");
        return false;
    }

    op.signature = EncodeBase64(vchSig);
    LogPrintf("✅ SignTokenOperationWithKey: Signed by %s\n", signer);
    return true;
}

static bool IsWitnessDestination(const CTxDestination& dest) {
    return boost::get<WitnessV0KeyHash>(&dest) != nullptr;
}

static bool IsLegacyDestination(const CTxDestination& dest) {
    return boost::get<PKHash>(&dest) != nullptr;
}

std::string TokenLedger::GetSignerAddress(const std::string& wallet, CWallet& w, bool witness)
{
    LOCK(m_mutex);

    auto it = m_wallet_signers.find(wallet);
    if (it != m_wallet_signers.end()) {
        if (witness && !it->second.witness.empty()) return it->second.witness;
        if (!witness && !it->second.legacy.empty()) return it->second.legacy;
    }

    const std::string dummy_msg = "signer_check";

    for (const auto& dest : w.GetAllDestinations()) {
        std::string sig;
        SigningResult err = w.SignMessage(dummy_msg, dest, sig);
        if (err != SigningResult::OK) continue;

        std::string addr = EncodeDestination(dest);

        if (witness && addr.substr(0, 4) != "itc1") continue; // native SegWit address check (like bc1 or itc1)
        if (!witness && addr.substr(0, 1) != "1") continue;   // legacy P2PKH check (optional)

        if (witness) {
            m_wallet_signers[wallet].witness = addr;
        } else {
            m_wallet_signers[wallet].legacy = addr;
        }
        Flush();
        LogPrintf("👤 Valid signer found for wallet '%s' -> %s\n", wallet, addr);
        return addr;
    }

    LogPrintf("❌ No valid signer address found for wallet '%s'\n", wallet);
    return "";
}

std::string BuildTokenMsg(const TokenOperation& op) {
    std::string msg = strprintf(
        "op=%d|from=%s|to=%s|spender=%s|token=%s|amount=%d|name=%s|symbol=%s|decimals=%d|timestamp=%d",
        (int)op.op,
        op.from,
        op.to,
        op.spender,
        op.token,
        op.amount,
        op.name,
        op.symbol,
        op.decimals,
        op.timestamp
    );
    if (!op.memo.empty()) {
        msg += "|memo=" + op.memo;
    }
    return msg;
}

bool TokenLedger::VerifySignature(const TokenOperation& op) const
{
    LOCK(m_mutex);  // Safe internal lock
    CTxDestination dest = DecodeDestination(op.signer);
    if (!IsValidDestination(dest)) {
        LogPrintf("❌ VerifyTokenOperation: Invalid signer address\n");
        return false;
    }
    std::string message = BuildTokenMsg(op);
    LogPrintf("✍️ VerifySignature: OP to verify: %s\n", message);
    MessageVerificationResult result = MessageVerify(op.signer, op.signature, message);

    if (result != MessageVerificationResult::OK) {
        LogPrintf("❌ VerifySignature: Failed for %s\n", op.signer);
        return false;
    }

    // Ensure the signer matches the expected address for this operation
    const std::string& expected = op.op == TokenOp::TRANSFERFROM ? op.spender : op.from;
    if (op.signer != expected) {
        LogPrintf("❌ VerifySignature: Signer %s does not match %s\n", op.signer, expected);
        return false;
    }

    LogPrintf("✅ VerifySignature: Signature valid for %s\n", op.signer);
    return true;
}

bool TokenLedger::RecordOperationOnChain(const std::string& wallet, const TokenOperation& op)
{
    std::shared_ptr<CWallet> from = GetWallet(wallet);
    if (!from) return false;
    LOCK(from->cs_wallet);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << op;
    CScript script;
    script << OP_RETURN << ToByteVector(ss);
    CRecipient recipient{script, 546, false};
    CCoinControl cc;
    std::vector<CRecipient> vecSend{recipient};
    CAmount nFeeRequired;
    int nChangePosRet = -1;
    bilingual_str err;
    CTransactionRef tx;
    FeeCalculation fee_calc;
    bool created = from->CreateTransaction(vecSend, tx, nFeeRequired, nChangePosRet, err, cc, fee_calc, !from->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    if (!created) return false;
    from->CommitTransaction(tx, {}, {});
    return true;
}

bool TokenLedger::ApplyOperation(const TokenOperation& op, const std::string& wallet_name, bool broadcast)
{
    LOCK(m_mutex);
    LogPrintf("📥 ApplyOperation called: op=%u token=%s from=%s to=%s signer=%s signature=%s\n", uint8_t(op.op), op.token, op.from, op.to, op.signer, op.signature);
    
    if (!VerifySignature(op)) {
        LogPrintf("❌ Signature invalid for op: %s\n", op.token);
        return false;
    }
    uint256 hash = TokenOperationHash(op);
    if (!m_seen_ops.insert(hash).second) {
        LogPrintf("⚠️ Token operation already seen: %s\n", hash.GetHex());
        return false;
    }
    bool ok = true;
    switch (op.op) {
    case TokenOp::CREATE: {
        int64_t height = ::ChainActive().Height();
        LogPrintf("🪙 Creating token: name=%s symbol=%s amount=%d\n", op.name, op.symbol, op.amount);
        CreateToken(op.from, op.token, op.amount, op.name, op.symbol, op.decimals, height);
        break;
    }
    case TokenOp::TRANSFER:
        ok = Transfer(op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::APPROVE:
        Approve(op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::TRANSFERFROM:
        ok = TransferFrom(op.spender, op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::INCREASE_ALLOWANCE:
        IncreaseAllowance(op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::DECREASE_ALLOWANCE:
        DecreaseAllowance(op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::BURN:
        if (m_token_meta.find(op.token) == m_token_meta.end()) return false;
        ok = Burn(op.from, op.token, op.amount);
        break;
    case TokenOp::MINT: {
        auto it = m_token_meta.find(op.token);
        if (it == m_token_meta.end() || it->second.operator_wallet != op.from) return false;
        ok = Mint(op.from, op.token, op.amount);
        break;
    }
    case TokenOp::TRANSFER_OWNERSHIP:
        ok = TransferOwnership(op.from, op.to, op.token);
        break;
    }
    if (ok) {
        // charge a network fee per configured rate and send it to the governance wallet
        unsigned int vsize = GetSerializeSize(op, PROTOCOL_VERSION);
        CAmount rate = (op.op == TokenOp::CREATE) ? m_create_fee_per_vbyte : m_fee_per_vbyte;
        CAmount fee = vsize * rate;
        if (fee < TOKEN_MIN_GOV_FEE) fee = TOKEN_MIN_GOV_FEE;
        if (broadcast && !wallet_name.empty() && SendGovernanceFee(wallet_name, fee)) {
            m_governance_fees += fee;
        }
        m_history[op.token].push_back(op);
        LogPrintf("token op %u token=%s from=%s to=%s amount=%d\n", uint8_t(op.op), op.token, op.from, op.to, op.amount);
        Flush();
        if (broadcast && !wallet_name.empty()) RecordOperationOnChain(wallet_name, op);
    }

    if (broadcast && ok) BroadcastTokenOp(op);
    return ok;
}

TokenLedger g_token_ledger;

std::vector<TokenOperation> TokenLedger::TokenHistory(const std::string& token, const std::string& address_filter) const
{
    LOCK(m_mutex);
    std::vector<TokenOperation> out;
    auto it = m_history.find(token);
    if (it == m_history.end()) return out;
    for (const auto& op : it->second) {
        if (!address_filter.empty()) {
            if (op.from != address_filter && op.to != address_filter && op.spender != address_filter) {
                continue;
            }
        }
        out.push_back(op);
    }
    return out;
}

std::string TokenLedger::GetTokenTxMemo(const std::string& token, const uint256& hash) const
{
    LOCK(m_mutex);
    auto it = m_history.find(token);
    if (it == m_history.end()) return "";
    for (const auto& op : it->second) {
        if (TokenOperationHash(op) == hash) {
            return op.memo;
        }
    }
    return "";
}

static bool DecodeTokenOp(const CScript& script, TokenOperation& op)
{
    CScript::const_iterator it = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(it, opcode)) return false;
    if (opcode != OP_RETURN) return false;
    if (!script.GetOp(it, opcode, data)) return false;
    if (data.empty()) return false;
    if (opcode > OP_PUSHDATA4) return false;

    // Try decoding using the current format which includes a memo flag
    try {
        CDataStream ss(data, SER_NETWORK, PROTOCOL_VERSION);
        ss >> op;
        return true;
    } catch (...) {
    }

    // Fallback to legacy format without the memo flag
    try {
        CDataStream ss(data, SER_NETWORK, PROTOCOL_VERSION);
        uint8_t op_val;
        ss >> op_val;
        op.op = static_cast<TokenOp>(op_val);
        ss >> op.from >> op.to >> op.spender >> op.token >> op.amount >> op.name
           >> op.symbol >> op.decimals >> op.timestamp >> op.signer >> op.signature;
        if (!ss.empty()) {
            ss >> op.memo;
        } else {
            op.memo.clear();
        }
        return true;
    } catch (...) {
    }
    return false;
}

bool TokenLedger::ReplayOperation(const TokenOperation& op, int64_t height)
{
    if (!VerifySignature(op)) return false;
    uint256 hash = TokenOperationHash(op);
    if (!m_seen_ops.insert(hash).second) return false;
    bool ok = true;
    switch (op.op) {
    case TokenOp::CREATE:
        CreateToken(op.from, op.token, op.amount, op.name, op.symbol, op.decimals, height);
        break;
    case TokenOp::TRANSFER:
        ok = Transfer(op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::APPROVE:
        Approve(op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::TRANSFERFROM:
        ok = TransferFrom(op.spender, op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::INCREASE_ALLOWANCE:
        IncreaseAllowance(op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::DECREASE_ALLOWANCE:
        DecreaseAllowance(op.from, op.to, op.token, op.amount);
        break;
    case TokenOp::BURN:
        if (m_token_meta.find(op.token) == m_token_meta.end()) return false;
        ok = Burn(op.from, op.token, op.amount);
        break;
    case TokenOp::MINT: {
        auto it = m_token_meta.find(op.token);
        if (it == m_token_meta.end() || it->second.operator_wallet != op.from) return false;
        ok = Mint(op.from, op.token, op.amount);
        break;
    }
    case TokenOp::TRANSFER_OWNERSHIP:
        ok = TransferOwnership(op.from, op.to, op.token);
        break;
    }
    if (ok) {
        m_history[op.token].push_back(op);
    }
    return ok;
}

bool TokenLedger::RescanFromHeight(int from_height)
{
    if (from_height < Params().TokenActivationHeight()) {
        from_height = Params().TokenActivationHeight();
    }
    {
        LOCK(m_mutex);
        m_balances.clear();
        m_allowances.clear();
        m_totalSupply.clear();
        m_token_meta.clear();
        m_history.clear();
        m_seen_ops.clear();
        m_governance_fees = 0;
    }

    for (int h = from_height; h <= ::ChainActive().Height(); ++h) {
        const CBlockIndex* index = ::ChainActive()[h];
        if (!index) continue;
        CBlock block;
        if (!ReadBlockFromDisk(block, index, Params().GetConsensus())) continue;
        for (const auto& tx : block.vtx) {
            for (const auto& out : tx->vout) {
                TokenOperation op;
                if (DecodeTokenOp(out.scriptPubKey, op)) {
                    LOCK(m_mutex);
                    ReplayOperation(op, h);
                }
            }
        }
    }
    LOCK(m_mutex);
    m_tip_height = ::ChainActive().Height();
    Flush();
    return true;
}

struct TokenLedgerStateV2 {
    std::map<std::pair<std::string, std::string>, CAmount> balances;
    std::map<AllowanceKey, CAmount> allowances;
    std::map<std::string, CAmount> totalSupply;
    std::map<std::string, TokenMeta> token_meta;
    std::map<std::string, std::vector<TokenOperation>> history;
    CAmount governance_fees{0};
    CAmount fee_per_vbyte{TOKEN_DEFAULT_FEE_PER_VBYTE};
    CAmount create_fee_per_vbyte{TOKEN_CREATE_FEE_PER_VBYTE};
    std::map<std::string, std::string> wallet_signers;
    int64_t tip_height{0};
    uint32_t version{TOKEN_DB_VERSION};

    SERIALIZE_METHODS(TokenLedgerStateV2, obj) {
        READWRITE(obj.balances, obj.allowances, obj.totalSupply, obj.token_meta, obj.history,
                  obj.governance_fees, obj.fee_per_vbyte, obj.create_fee_per_vbyte,
                  obj.wallet_signers, obj.tip_height, obj.version);
    }
};

bool TokenLedger::Load()
{
    LOCK(m_mutex);

    if (!g_token_db) {
        g_token_db = std::make_unique<CDBWrapper>(GetDataDir() / "tokens", 1 << 20, false, false, true);
    }

    uint32_t version = 0;
    g_token_db->Read('v', version);

    TokenLedgerState state;

    if (version >= 3) {
        if (!g_token_db->Read('s', state)) return false;
    } else {
        TokenLedgerStateV2 state_v2;
        if (!g_token_db->Read('s', state_v2)) return false;

        state.balances = state_v2.balances;
        state.allowances = state_v2.allowances;
        state.totalSupply = state_v2.totalSupply;
        state.token_meta = state_v2.token_meta;
        state.history = state_v2.history;
        state.governance_fees = state_v2.governance_fees;
        state.fee_per_vbyte = state_v2.fee_per_vbyte;
        state.create_fee_per_vbyte = state_v2.create_fee_per_vbyte;

        // Upgrade old signer format
        for (const auto& kv : state_v2.wallet_signers) {
            WalletSigners ws;
            if (kv.second.rfind("itc1", 0) == 0) {
                ws.witness = kv.second;
            } else {
                ws.legacy = kv.second;
            }
            state.wallet_signers[kv.first] = ws;
        }

        state.tip_height = state_v2.tip_height;
    }

    if (version > TOKEN_DB_VERSION) return false;

    if (version < TOKEN_DB_VERSION) {
        state.version = TOKEN_DB_VERSION;
        g_token_db->Write('v', TOKEN_DB_VERSION);
        g_token_db->Write('s', state);
    }

    m_balances = state.balances;
    m_allowances = state.allowances;
    m_totalSupply = state.totalSupply;
    m_token_meta = state.token_meta;
    m_history = state.history;
    m_governance_fees = state.governance_fees;
    m_fee_per_vbyte = state.fee_per_vbyte;
    m_create_fee_per_vbyte = state.create_fee_per_vbyte;
    m_wallet_signers = state.wallet_signers;
    m_tip_height = state.tip_height;

    if (m_tip_height == 0) m_tip_height = Params().TokenActivationHeight() - 1;
    m_governance_wallet = Params().GovernanceWallet();

    return true;
}

bool TokenLedger::Flush() const
{
    LOCK(m_mutex);
    if (!g_token_db) {
        g_token_db = std::make_unique<CDBWrapper>(GetDataDir() / "tokens", 1 << 20, false, false, true);
    }
    TokenLedgerState state;
    state.balances = m_balances;
    state.allowances = m_allowances;
    state.totalSupply = m_totalSupply;
    state.token_meta = m_token_meta;
    state.history = m_history;
    state.governance_fees = m_governance_fees;
    state.fee_per_vbyte = m_fee_per_vbyte;
    state.create_fee_per_vbyte = m_create_fee_per_vbyte;
    state.wallet_signers = m_wallet_signers;
    state.tip_height = m_tip_height;
    state.version = TOKEN_DB_VERSION;
    CDBBatch batch(*g_token_db);
    batch.Write('s', state);
    batch.Write('v', TOKEN_DB_VERSION);
    return g_token_db->WriteBatch(batch, true);
}

void TokenLedger::SetFeeRate(CAmount fee_per_vbyte)
{
    LOCK(m_mutex);
    m_fee_per_vbyte = fee_per_vbyte;
}

CAmount TokenLedger::FeeRate() const
{
    LOCK(m_mutex);
    return m_fee_per_vbyte;
}

int TokenLedger::GetDecimals(const std::string& token_id) const {
    // auto it = tokens.find(token_id);
    // if (it == tokens.end()) return 16; // Default to 16 if not found
    // return it->second.decimals;
    return 8;
}

void TokenLedger::ProcessBlock(const CBlock& block, int height)
{
    for (const auto& tx : block.vtx) {
        for (const auto& out : tx->vout) {
            TokenOperation op;
            if (DecodeTokenOp(out.scriptPubKey, op)) {
                LOCK(m_mutex);
                ReplayOperation(op, height);
            }
        }
    }
    LOCK(m_mutex);
    m_tip_height = height;
    Flush();
}

