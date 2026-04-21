// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <chrono>
#include "arith_uint256.h"

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include "pow/yespower.h"
#include "consensus/consensus.h"
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include "primitives/block.h"

#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>

#include <atomic>
#include <validation.h>
#include <shutdown.h>
#include <util/time.h>
#include <thread>
#include <memory>
#include <logging.h>
#include <script/standard.h>
#include <script/descriptor.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>
#include <wallet/walletdb.h>
#include <wallet/fees.h>
#include <util/strencodings.h>
#include <rpc/blockchain.h> 
#include <key_io.h> 
#include <pubkey.h>
#include <algorithm>
#include <utility>

// using progpow::hash256; // we're not using prog anymore

CTxMemPool& EnsureMemPool(NodeContext& node);

extern bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock>& block, bool fForceProcessing, bool* fNewBlock);

static std::atomic<bool> foundBlock(false);
static std::atomic<uint64_t> totalHashes(0);
static std::atomic<bool> fGenerating(false);

void GenerateBitcoins(bool fGenerate, CConnman* connman, int nThreads, const std::string& payoutAddress, const util::Ref& context)
{
    fGenerating = fGenerate;
    if (!fGenerate)
        return;

    // Extract the mempool from context
    const CTxMemPool& mempool = EnsureMemPool(context);

    std::thread([=, &mempool]() {
        while (fGenerating && !ShutdownRequested()) {
            foundBlock.store(false);
            totalHashes.store(0);

            LogPrintf("♻️ Launching %d miner threads...\n", nThreads);

            const CChainParams& chainparams = Params();
            CTxDestination dest = DecodeDestination(payoutAddress);
            if (!IsValidDestination(dest)) {
                LogPrintf("❌ Invalid payout address: %s\n", payoutAddress);
                return;
            }
            CScript scriptPubKey = GetScriptForDestination(dest);
            
            BlockAssembler assembler(mempool, chainparams);

            std::unique_ptr<CBlockTemplate> pblocktemplate = assembler.CreateNewBlock(scriptPubKey);
            if (!pblocktemplate) {
                LogPrintf("⚠️ Block template is null\n");
                continue;
            }

            CBlock originalBlock = pblocktemplate->block;
            LogPrintf("🧾 Block includes %d transactions\n", originalBlock.vtx.size() - 1);

            for (int threadId = 0; threadId < nThreads; ++threadId) {
                std::thread([=, &mempool]() mutable {
                    LogPrintf("⛏️ Starting miner thread %d...\n", threadId);
                    static thread_local yespower_local_t shared;
                    static thread_local bool initialized = false;
                    if (!initialized) {
                        yespower_init_local(&shared);
                        initialized = true;
                    }

                    CBlock block = originalBlock;
                    block.nTime = std::max(GetAdjustedTime(), ::ChainActive().Tip()->GetMedianTimePast() + 1);

                    // Save the original witness stack before mutation
                    const auto witnessStack = originalBlock.vtx[0]->vin[0].scriptWitness.stack;

                    // This modifies block.vtx[0] by rebuilding the coinbase
                    static thread_local unsigned int nExtraNonce = 0;
                    IncrementExtraNonce(&block, ::ChainActive().Tip(), nExtraNonce);

                    // Now restore the original witness stack
                    if (witnessStack.size() == 1 && witnessStack[0].size() == 32) {
                        CMutableTransaction coinbaseTx(*block.vtx[0]);
                        coinbaseTx.vin[0].scriptWitness.stack = witnessStack;
                        block.vtx[0] = MakeTransactionRef(coinbaseTx);
                    }
                    // block.vtx[0] = MakeTransactionRef(coinbaseTx);
                    // block.hashMerkleRoot = BlockMerkleRoot(block);
                    block.vchWitness = {GenerateCoinbaseCommitment(block, ::ChainActive().Tip(), Params().GetConsensus())};
                    // uint256 hashTarget = ArithToUint256(arith_uint256().SetCompact(block.nBits));
                    arith_uint256 bnTarget;
                    bnTarget.SetCompact(block.nBits);
                    uint256 hashTarget = ArithToUint256(bnTarget);

                    uint64_t hashesDone = 0;
                    int64_t hashStart = GetTimeMillis();
                    int printCount = 0;

                    uint32_t startNonce = GetRand(std::numeric_limits<uint32_t>::max());
                    for (uint32_t nonce = startNonce + threadId; nonce < std::numeric_limits<uint32_t>::max(); nonce += nThreads) {
                        if (ShutdownRequested() || !fGenerating || foundBlock.load())
                            return;

                        ++hashesDone;
                        block.nNonce = nonce;
                        block.nTime = std::max(GetAdjustedTime(), ::ChainActive().Tip()->GetMedianTimePast() + 1);

                        int nHeight = ::ChainActive().Height() + 1;
                        uint256 hash;
                        if (nHeight >= 1) {
                            hash = YespowerHash(block, &shared, nHeight);
                        } else {
                            hash = block.GetHash();
                        }

                        if (printCount < 10) {
                            LogPrintf("🔍 Try: Hash: %s Target: %s\n", hash.ToString(), hashTarget.ToString());
                            printCount++;
                        }

                        if (UintToArith256(hash) <= UintToArith256(hashTarget)) {
                            LogPrintf("✅ [thread %d] Valid block found! Hash: %s\n", threadId, hash.ToString());
                            LogPrintf("🧩 Merkle Root: %s\n", block.hashMerkleRoot.ToString());
                            LogPrintf("🎯 Coinbase TXID: %s\n", block.vtx[0]->GetHash().ToString());
                            LogPrintf("🧱 Mining block with hashPrevBlock = %s | Expected = %s\n", block.hashPrevBlock.ToString(), ::ChainActive().Tip()->GetBlockHash().ToString());
                            std::shared_ptr<const CBlock> pblockShared = std::make_shared<const CBlock>(block);
                            bool fNewBlock = false;
                            if (!g_chainman.ProcessNewBlock(chainparams, pblockShared, true, &fNewBlock)) {
                                LogPrintf("❌ [thread %d] Failed to process new block\n", threadId);
                            } else {
                                LogPrintf("✅ [thread %d] Block accepted!\n", threadId);
                                GetMainSignals().NewPoWValidBlock(::ChainActive().Tip(), pblockShared);
                            }

                            foundBlock.store(true);
                            int64_t finalElapsed = GetTimeMillis() - hashStart;
                            if (finalElapsed > 0 && hashesDone > 0) {
                                double finalRate = static_cast<double>(hashesDone) / (finalElapsed / 1000.0);
                                double displayRate = finalRate;
                                std::string unit = "H/s";
                                if (finalRate >= 1e9) {
                                    displayRate /= 1e9;
                                    unit = "GH/s";
                                } else if (finalRate >= 1e6) {
                                    displayRate /= 1e6;
                                    unit = "MH/s";
                                } else if (finalRate >= 1e3) {
                                    displayRate /= 1e3;
                                    unit = "kH/s";
                                }
                                LogPrintf("⚡ [thread %d] Final Hashrate: %.2f %s\n", threadId, displayRate, unit.c_str());
                            }

                            return;
                        }

                        if (hashesDone % 1000 == 0) {
                            int64_t elapsed = GetTimeMillis() - hashStart;
                            if (elapsed >= 5000) {
                                double rate = (double)hashesDone / (elapsed / 1000.0);
                                std::string unit = "H/s";
                                if (rate >= 1e9) {
                                    rate /= 1e9;
                                    unit = "GH/s";
                                } else if (rate >= 1e6) {
                                    rate /= 1e6;
                                    unit = "MH/s";
                                } else if (rate >= 1e3) {
                                    rate /= 1e3;
                                    unit = "kH/s";
                                }
                                LogPrintf("⚡ [thread %d] Hashrate: %.2f %s\n", threadId, rate, unit);
                                totalHashes += hashesDone;
                                hashesDone = 0;
                                hashStart = GetTimeMillis();
                            }
                        }
                    }
                }).detach();
            }

            while (!ShutdownRequested() && fGenerating && !foundBlock.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            if (foundBlock.load()) {
                LogPrintf("🔁 Restarting mining after block found...\n");
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
    }).detach();
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    GenerateCoinbaseCommitment(block, WITH_LOCK(cs_main, return LookupBlockIndex(block.hashPrevBlock)), Params().GetConsensus());

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
}

BlockAssembler::BlockAssembler(const CTxMemPool& mempool, const CChainParams& params, const Options& options)
    : chainparams(params),
      m_mempool(mempool)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(MAX_BLOCK_WEIGHT - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions()
{
    // Block resource limits
    // If -blockmaxweight is not given, limit to DEFAULT_BLOCK_MAX_WEIGHT
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
    CAmount n = 0;
    if (gArgs.IsArgSet("-blockmintxfee") && ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n)) {
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CTxMemPool& mempool, const CChainParams& params)
    : BlockAssembler(mempool, params, DefaultOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

Optional<int64_t> BlockAssembler::m_last_block_num_txs{nullopt};
Optional<int64_t> BlockAssembler::m_last_block_weight{nullopt};

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end
    
    LOCK2(cs_main, m_mempool.cs);
    CBlockIndex* pindexPrev = ::ChainActive().Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;
    // int32_t kawpowVersion = VERSIONBITS_KAWPOW;
    int32_t defaultVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());

    pblock->nVersion = defaultVersion;

    // Append SEGWIT bit if active not necessary
    // if (IsWitnessEnabled(pindexPrev, chainparams.GetConsensus())) {
    //     pblock->nVersion |= VersionBitsMask(chainparams.GetConsensus(), Consensus::DEPLOYMENT_SEGWIT);
    // }

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);
    
    const Consensus::Params& params = Params().GetConsensus();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
    const int64_t now = GetAdjustedTime();
    const int64_t safeTime = std::max(nMedianTimePast + 1, now);
    if (nHeight >= params.difficultyForkHeight) {
        pblock->nTime = std::min(safeTime, nMedianTimePast + 20 * 60);
    } else {
        pblock->nTime = now; // legacy behavior
    }
    LogPrintf("⏱️ Block time set at height=%d: nTime=%d, MTP=%d, Now=%d\n", nHeight, pblock->nTime, nMedianTimePast, now);
    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization).
    // Note that the mempool would accept transactions with witness data before
    // IsWitnessEnabled, but we would only ever mine blocks after IsWitnessEnabled
    // unless there is a massive block reorganization with the witness softfork
    // not activated.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).

    LogPrintf("Before addPackageTxs: nBlockWeight = %d, nBlockTx = %d, nFees = %ld\n", nBlockWeight, nBlockTx, nFees);
    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    // Enable witness inclusion if SegWit is active
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus());
    LogPrintf("fIncludeWitness = %d\n", fIncludeWitness);
    addPackageTxs(m_mempool, nPackagesSelected, nDescendantsUpdated);
    LogPrintf("After addPackageTxs: nBlockWeight = %d, nBlockTx = %d, nFees = %ld\n", nBlockWeight, nBlockTx, nFees);
    LogPrintf("✅ m_mempool loaded with %zu transactions\n", m_mempool.mapTx.size());
    int64_t nTime1 = GetTimeMicros();

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    bool burn_fees = nHeight >= 1 && nHeight <= chainparams.GetConsensus().nFeeBurnEndHeight; // fees burned until 
    // Basis points (per 10,000)
    static constexpr int GOV_BPS = 7300; // 73.00%
    static constexpr int OP_BPS  =  500; // 5.00%
    static constexpr int BPS_DENOM = 10000;
    CAmount blockReward = GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    // Governance + dev/ops
    CAmount governanceReward = (blockReward * GOV_BPS) / BPS_DENOM; // 51% goes to governance & 22% development/operations
    // CAmount governanceReward = blockReward * 73 / 100; 
    CTxDestination opDest = DecodeDestination(chainparams.NodeOperatorWallet());
    bool hasOpDest = IsValidDestination(opDest);
    CAmount operatorReward = hasOpDest ? (blockReward * OP_BPS) / BPS_DENOM : 0; // 5% goes to node operator 
    // CAmount operatorReward = hasOpDest ? blockReward * 5 / 100 : 0; 
    if (!burn_fees) blockReward += nFees;
    coinbaseTx.vout.resize(hasOpDest ? 3 : 2);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = blockReward - governanceReward - operatorReward;
    CTxDestination govDest = DecodeDestination(chainparams.GovernanceWallet());
    LogPrintf("[builder] baseReward=%d gov=%d op=%d\n",
          blockReward, governanceReward, operatorReward);

    if (IsValidDestination(govDest)) {
        coinbaseTx.vout[1].scriptPubKey = GetScriptForDestination(govDest);
        coinbaseTx.vout[1].nValue = governanceReward;
    } else {
        // Fallback: pay entire reward to miner if governance address invalid
        coinbaseTx.vout.resize(1);
        coinbaseTx.vout[0].nValue = blockReward;
    }
    if (hasOpDest) {
        coinbaseTx.vout[2].scriptPubKey = GetScriptForDestination(opDest);
        coinbaseTx.vout[2].nValue = operatorReward;
    }
    // coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    coinbaseTx.vin[0].scriptSig = (CScript() << nHeight << ParseHex("f000000ff111111f"));

    // Add witness nonce to scriptWitness
    coinbaseTx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(32, 0x00)); // 32-byte reserved nonce
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    if (fIncludeWitness) {
        const uint256 witnessRoot = BlockWitnessMerkleRoot(*pblock, nullptr);
        static const unsigned char nonce[32] = {0}; // same nonce as in scriptWitness

        // Commitment = SHA256(SHA256(witnessRoot || nonce))
        CHash256 hash;
        hash.Write(Span<const unsigned char>(witnessRoot.begin(), 32));
        hash.Write(Span<const unsigned char>(nonce, 32));
        uint256 commitment;
        hash.Finalize(Span<unsigned char>(commitment.begin(), commitment.size()));

        CScript witness_commitment_script = CScript() << OP_RETURN
            << std::vector<unsigned char>{0xaa, 0x21, 0xa9, 0xed}
            << std::vector<unsigned char>(commitment.begin(), commitment.end());

        // Append witness commitment to coinbase outputs
        coinbaseTx.vout.push_back(CTxOut(0, witness_commitment_script));
    }
    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    pblocktemplate->vTxFees[0] = burn_fees ? 0 : -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    BlockValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(
            ("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (CTxMemPool::txiter it : package) {
        const CTransaction& tx = it->GetTx();

        if (!IsFinalTx(tx, nHeight, nLockTimeCutoff)) {
            LogPrintf("❌ Rejected tx %s: not final (locktime) — nHeight=%d, nLockTimeCutoff=%d\n",
                      tx.GetHash().ToString(), nHeight, nLockTimeCutoff);
            return false;
        }

        if (!fIncludeWitness && tx.HasWitness()) {
            LogPrintf("❌ Rejected tx %s: contains witness data but fIncludeWitness=0 (SegWit not active yet)\n",
                      tx.GetHash().ToString());
            return false;
        }

        LogPrintf("✅ Accepted tx %s | Version: %d | Witness: %s | LockTime: %u\n",
                  tx.GetHash().ToString(), tx.nVersion,
                  tx.HasWitness() ? "yes" : "no", tx.nLockTime);
    }

    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        m_mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert(it != m_mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(const CTxMemPool& mempool, int &nPackagesSelected, int &nDescendantsUpdated)
{
    indexed_modified_transaction_set mapModifiedTx;
    CTxMemPool::setEntries failedTx;

    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    LogPrintf("📦 addPackageTxs: mempool has %zu transactions\n", mempool.mapTx.size());

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty()) {
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
            SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        bool fUsingModified = false;
        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            iter = modit->iter;
            fUsingModified = true;
        } else {
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                iter = modit->iter;
                fUsingModified = true;
            } else {
                ++mi;
            }
        }

        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            LogPrintf("❌ Skipping tx %s — fee %ld too low for size %llu, required: %ld\n",
                iter->GetTx().GetHash().ToString(), packageFees, packageSize, blockMinFeeRate.GetFee(packageSize));
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            ++nConsecutiveFailed;
            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
                nBlockWeight > nBlockMaxWeight - 4000) {
                break;
            }
            continue;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            LogPrintf("❌ TestPackage failed for tx %s at height=%d\n",
                iter->GetTx().GetHash().ToString(), nHeight);
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            ++nConsecutiveFailed;
            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
                nBlockWeight > nBlockMaxWeight - 4000) {
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        m_mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        const CTransaction& tx = iter->GetTx();
        LogPrintf("🔍 Inspecting tx %s | Version: %d | nLockTime: %u | Inputs: %zu | Outputs: %zu | Witness: %s\n",
            tx.GetHash().ToString(), tx.nVersion, tx.nLockTime, tx.vin.size(), tx.vout.size(),
            tx.HasWitness() ? "yes" : "no");

        if (!TestPackageTransactions(ancestors)) {
            LogPrintf("❌ TestPackageTransactions failed for tx %s at height=%d\n",
                iter->GetTx().GetHash().ToString(), nHeight);
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        nConsecutiveFailed = 0;
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i = 0; i < sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce));
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}
