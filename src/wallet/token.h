#ifndef BITCOIN_WALLET_TOKEN_H
#define BITCOIN_WALLET_TOKEN_H

#include <net.h>
#include <net_processing.h>
#include <validationinterface.h>
#include <netmessagemaker.h>
#include <amount.h>
#include <map>
#include <string>
#include <tuple>
#include <sync.h>
#include <set>
#include <vector>
#include <hash.h>
#include <serialize.h>
#include <wallet/wallet.h>
#include <primitives/block.h>
#include <cstdint>

static const uint32_t TOKEN_DB_VERSION = 3;
//! Default fee rate for token operations (excluding create)
static const CAmount TOKEN_DEFAULT_FEE_PER_VBYTE = 10000; // 10k sat/vB
//! Special fee rate applied when creating new tokens
static const CAmount TOKEN_CREATE_FEE_PER_VBYTE = 10000000; // 10M sat/vB
//! Minimum governance fee per operation (0.075 ITC)
static const CAmount TOKEN_MIN_GOV_FEE = 7500000;

enum class TokenOp : uint8_t {
    CREATE = 0,
    TRANSFER = 1,
    APPROVE = 2,
    TRANSFERFROM = 3,
    INCREASE_ALLOWANCE = 4,
    DECREASE_ALLOWANCE = 5,
    BURN = 6,
    MINT = 7,
    TRANSFER_OWNERSHIP = 8
};

struct TokenOperation {
    TokenOp op{TokenOp::CREATE};
    std::string from;
    std::string to;
    std::string spender;
    std::string token;
    CAmount amount{0};
    std::string name;
    std::string symbol;
    uint8_t decimals{0};
    int64_t timestamp{0};
    std::string signer;
    std::string signature;
    std::string wallet_name;
    std::string memo;

    std::string ToString() const {
        return strprintf(
            "op=%d token=%s from=%s signer=%s ts=%d",
            static_cast<int>(op),   // 👈 Cast the enum
            token,
            from,
            signer.c_str(),
            timestamp
        );
    }


    SERIALIZE_METHODS(TokenOperation, obj) {
        uint8_t op_val;
        if (ser_action.ForRead()) {
            READWRITE(op_val);
            const_cast<TokenOp&>(obj.op) = static_cast<TokenOp>(op_val);
        } else {
            op_val = static_cast<uint8_t>(obj.op);
            READWRITE(op_val);
        }
        READWRITE(obj.from, obj.to, obj.spender, obj.token, obj.amount,
                  obj.name, obj.symbol, obj.decimals, obj.timestamp,
                  obj.signer, obj.signature);
    
        // Add optional memo field with explicit flag
        uint8_t hasMemo;
        if (ser_action.ForRead()) {
            READWRITE(hasMemo);
            if (hasMemo) {
                READWRITE(obj.memo);
            } else {
                const_cast<std::string&>(obj.memo).clear();
            }
        } else {
            hasMemo = !obj.memo.empty();
            READWRITE(hasMemo);
            if (hasMemo) {
                READWRITE(obj.memo);
            }
        }
    }
};

struct TokenMeta {
    std::string name;
    std::string symbol;
    uint8_t decimals{0};
    std::string operator_wallet;
    int64_t creation_height{0};

    SERIALIZE_METHODS(TokenMeta, obj) {
        READWRITE(obj.name, obj.symbol, obj.decimals, obj.operator_wallet, obj.creation_height);
    }
};

struct AllowanceKey {
    std::string owner;
    std::string spender;
    std::string token;

    SERIALIZE_METHODS(AllowanceKey, obj) {
        READWRITE(obj.owner, obj.spender, obj.token);
    }

    bool operator<(const AllowanceKey& o) const {
        return std::tie(owner, spender, token) < std::tie(o.owner, o.spender, o.token);
    }
};

uint256 TokenOperationHash(const TokenOperation& op);
void BroadcastTokenOp(const TokenOperation& op);
//! Build deterministic message string for signing token operations
std::string BuildTokenMsg(const TokenOperation& op);
bool IsValidTokenId(const std::string& token);
std::string GenerateTokenId(const std::string& creator, const std::string& name);

struct WalletSigners {
    std::string legacy;
    std::string witness;

    SERIALIZE_METHODS(WalletSigners, obj)
    {
        READWRITE(obj.legacy, obj.witness);
    }
};

struct TokenLedgerState {
    std::map<std::pair<std::string, std::string>, CAmount> balances;
    std::map<AllowanceKey, CAmount> allowances;
    std::map<std::string, CAmount> totalSupply;
    std::map<std::string, TokenMeta> token_meta;
    std::map<std::string, std::vector<TokenOperation>> history;
    CAmount governance_fees{0};
    CAmount fee_per_vbyte{TOKEN_DEFAULT_FEE_PER_VBYTE};
    CAmount create_fee_per_vbyte{TOKEN_CREATE_FEE_PER_VBYTE};
    std::map<std::string, WalletSigners> wallet_signers;
    int64_t tip_height{0};
    uint32_t version{TOKEN_DB_VERSION};

    SERIALIZE_METHODS(TokenLedgerState, obj) {
        READWRITE(obj.balances, obj.allowances, obj.totalSupply, obj.token_meta, obj.history,
                  obj.governance_fees, obj.fee_per_vbyte, obj.create_fee_per_vbyte,
                  obj.wallet_signers, obj.tip_height, obj.version);
    }
};

class TokenLedger {
public:
    bool ApplyOperation(const TokenOperation& op, const std::string& wallet_name = "", bool broadcast = true);
    bool Load();
    bool Flush() const;

    void SetFeeRate(CAmount fee_per_vbyte);
    CAmount FeeRate() const;
    CAmount GovernanceBalance() const;

    CAmount GetBalance(const std::string& wallet, const std::string& token) const;
    CAmount Balance(const std::string& wallet, const std::string& token) const;
    CAmount Allowance(const std::string& owner, const std::string& spender, const std::string& token) const;
    CAmount TotalSupply(const std::string& token) const;
    Optional<TokenMeta> GetTokenMeta(const std::string& token) const;

    std::vector<std::tuple<std::string, std::string, std::string>> ListWalletTokens(const std::string& address) const;
    std::vector<std::tuple<std::string, std::string, std::string>> ListAllTokens() const;
    std::vector<TokenOperation> TokenHistory(const std::string& token, const std::string& address_filter = "") const;
    std::string GetTokenTxMemo(const std::string& token, const uint256& hash) const;

    bool RescanFromHeight(int from_height);
    bool ReplayOperation(const TokenOperation& op, int64_t height) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    std::string GetSignerAddress(const std::string& wallet, CWallet& w, bool witness);
    bool VerifySignature(const TokenOperation& op) const;
    void ProcessBlock(const CBlock& block, int height);
    int GetDecimals(const std::string& token_id) const;
    bool SignTokenOperation(TokenOperation& op, CWallet& wallet, const std::string& walletName, bool witness);
    bool SignTokenOperationWithKey(TokenOperation& op, const std::string& wifKey);

private:
    void CreateToken(const std::string& wallet, const std::string& token, CAmount amount,
                     const std::string& name, const std::string& symbol, uint8_t decimals, int64_t height);
    void RegisterToken(const std::string& token, const std::string& name,
                       const std::string& symbol, uint8_t decimals, const std::string& owner, int64_t height);
    void Approve(const std::string& owner, const std::string& spender, const std::string& token, CAmount amount);
    void IncreaseAllowance(const std::string& owner, const std::string& spender, const std::string& token, CAmount amount);
    void DecreaseAllowance(const std::string& owner, const std::string& spender, const std::string& token, CAmount amount);
    bool Transfer(const std::string& from, const std::string& to, const std::string& token, CAmount amount);
    bool TransferFrom(const std::string& spender, const std::string& from, const std::string& to, const std::string& token, CAmount amount);
    bool Burn(const std::string& wallet, const std::string& token, CAmount amount);
    bool Mint(const std::string& wallet, const std::string& token, CAmount amount);
    bool TransferOwnership(const std::string& from, const std::string& to, const std::string& token);
    bool SendGovernanceFee(const std::string& wallet, CAmount fee);
    bool RecordOperationOnChain(const std::string& wallet, const TokenOperation& op);

    mutable RecursiveMutex m_mutex;
    std::map<std::pair<std::string, std::string>, CAmount> m_balances;
    std::map<AllowanceKey, CAmount> m_allowances;
    std::map<std::string, CAmount> m_totalSupply;
    std::map<std::string, TokenMeta> m_token_meta;
    std::set<uint256> m_seen_ops;
    std::map<std::string, std::vector<TokenOperation>> m_history;

    std::string m_governance_wallet{"itc1qwccnjw6gz49vlsjvf3f6wvamltmqdykwmh0r4r"};
    CAmount m_governance_fees{0};
    CAmount m_fee_per_vbyte{TOKEN_DEFAULT_FEE_PER_VBYTE};
    CAmount m_create_fee_per_vbyte{TOKEN_CREATE_FEE_PER_VBYTE};
    std::map<std::string, WalletSigners> m_wallet_signers;
    int64_t m_tip_height{0};
};

extern TokenLedger g_token_ledger;

bool VerifyMessage(const CTxDestination& address, const std::string& signature, const std::string& message);
void RegisterTokenValidationInterface();
void UnregisterTokenValidationInterface();

#endif // BITCOIN_WALLET_TOKEN_H
