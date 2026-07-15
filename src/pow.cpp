// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>
#include <arith_uint256.h>
#include <chain.h>
#include "pow/yespower.h"
#include "validation.h"      // for cs_main
#include "logging.h"         // for BCLog and LogPrint
#include <primitives/block.h>
#include <uint256.h>

unsigned int DarkGravityWave3(const CBlockIndex* pindexLast, const Consensus::Params& params);
unsigned int DarkGravityWave3Nova(const CBlockIndex* pindexLast, const Consensus::Params& params);
unsigned int Lwma3(const CBlockIndex* pindexLast, const Consensus::Params& params);

// Dual-PoW helpers ------------------------------------------------------------
// At `sha256ReactivationHeight` SHA256 becomes the primary PoW and is
// ALWAYS accepted from that height onward. Yespower is retained as an
// additive emergency fallback that arms when the time gap between the
// candidate block and its parent exceeds `nPowEmergencyTimeout` seconds.
//
//   Pre-reactivation : Yespower is the main PoW (historical chain).
//   Post-reactivation: SHA256 is always valid; Yespower is ALSO valid for
//                      a given block only when the time-based emergency
//                      trigger is armed for that block.
static inline bool IsPostSha256Fork(int nHeight, const Consensus::Params& params)
{
    return nHeight >= params.sha256ReactivationHeight;
}

// The powLimit that applies for difficulty retargeting at a given next-height.
// Post-reactivation we target SHA256 difficulty; pre-reactivation we stay
// on Yespower.
static inline uint256 GetPowLimitForHeight(int nHeight, const Consensus::Params& params)
{
    if (IsPostSha256Fork(nHeight, params)) return params.powLimit;
    if (nHeight >= params.yespowerForkHeight) return params.powLimitYespower;
    return params.powLimit;
}

// Emergency / stall trigger (TIME-BASED).
//
// Once SHA256 is live ASICs will pin difficulty, so a target-based trigger
// can never fire. Instead we look at how long the candidate block claims it
// has been since the previous block. If that gap exceeds
// params.nPowEmergencyTimeout seconds, the Yespower fallback is armed for
// this block (Yespower is accepted IN ADDITION to SHA256, never instead of).
//
// prevBlockTime < 0 means "unknown" (reload / reindex / unit tests). In that
// case we arm the fallback permissively so already-validated blocks can be
// reloaded from disk without difficulty.
static inline bool IsEmergencyArmed(int64_t blockTime, int64_t prevBlockTime, const Consensus::Params& params)
{
    if (params.nPowEmergencyTimeout <= 0) return false;     // disabled
    if (prevBlockTime < 0)                return true;      // unknown -> permissive
    return (blockTime - prevBlockTime) > params.nPowEmergencyTimeout;
}

// Transition grace window: during the first nPowYespowerGraceBlocks blocks
// at and after sha256ReactivationHeight, Yespower is accepted unconditionally
// (no inter-block-time arming required). SHA256 is also accepted throughout.
// After the window closes, Yespower reverts to emergency-only.
static inline bool IsYespowerGraceActive(int nHeight, const Consensus::Params& params)
{
    if (params.nPowYespowerGraceBlocks <= 0) return false;
    if (nHeight < params.sha256ReactivationHeight) return false;
    return nHeight < (params.sha256ReactivationHeight + params.nPowYespowerGraceBlocks);
}
// ----------------------------------------------------------------------------
// BITCOIN LEGACY DAA
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    const int nextHeight = pindexLast->nHeight + 1;
    LogPrintf("GetNextWorkRequired: height=%d using %s\n", pindexLast->nHeight,
          IsPostSha256Fork(nextHeight, params) ? "SHA256 target (post-fork)"
                                               : (nextHeight >= params.yespowerForkHeight ? "Yespower target" : "SHA256 target"));

    if (nextHeight >= params.nextDifficultyFork2Height) {
        return DarkGravityWave3Nova(pindexLast, params);
    }

    arith_uint256 limit = UintToArith256(GetPowLimitForHeight(nextHeight, params));
    LogPrintf("💡 GetNextWorkRequired: powLimit used = %s\n", limit.ToString());
    unsigned int nProofOfWorkLimit = limit.GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

// DGW3
unsigned int DarkGravityWave3Nova(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    int nextHeight = pindexLast->nHeight + 1;
    const int nPastBlocks = (nextHeight >= params.nextDifficultyFork5Height) ? 12 : 24;

    arith_uint256 limit = UintToArith256(GetPowLimitForHeight(nextHeight, params));
    LogPrintf("💡 DGW3-NOVA: powLimit used = %s (%s)\n", limit.ToString(),
              IsPostSha256Fork(nextHeight, params) ? "SHA256-post-fork" : "Yespower-era");

    if (nextHeight < nPastBlocks)
        return limit.GetCompact();

    const CBlockIndex* pindex = pindexLast;
    arith_uint256 pastDifficultyAverage, pastDifficultyAveragePrev;
    int64_t actualTimespan = 0, lastBlockTime = 0;

    for (int i = 0; i < nPastBlocks; ++i) {
        if (!pindex) break;

        arith_uint256 currentDifficulty = arith_uint256().SetCompact(pindex->nBits);
        if (i == 0)
            pastDifficultyAverage = currentDifficulty;
        else
            pastDifficultyAverage = ((pastDifficultyAveragePrev * i) + currentDifficulty) / (i + 1);

        pastDifficultyAveragePrev = pastDifficultyAverage;

        if (lastBlockTime > 0)
            actualTimespan += lastBlockTime - pindex->GetBlockTime();

        lastBlockTime = pindex->GetBlockTime();
        pindex = pindex->pprev;
    }

    const int64_t targetTimespan = nPastBlocks * params.nPowTargetSpacing;
    const bool v9 = nextHeight >= params.nextDifficultyFork5Height;

    // Define clamping bounds
    int64_t minTimespanClamp = (targetTimespan / 3);
    int64_t maxTimespanClamp = (targetTimespan * 3);

    int64_t emergencyClamp = v9 ? (targetTimespan / 3) : (targetTimespan / 6);
    int64_t minSolveClamp = v9 ? (targetTimespan / 4) : (targetTimespan / 8);

    const int64_t minSolveTime = 12;

    int64_t actualSolveTime = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();
    int64_t unclampedActualTimespan = actualTimespan;  // Save raw timespan

    // Rolling median of solve times (Fork 8)
    int64_t rollingSolveTime = actualSolveTime;
    if (v9) {
        std::vector<int64_t> solveTimes;
        const CBlockIndex* cursor = pindexLast;
        for (int i = 0; i < std::min(nPastBlocks, 9); ++i) {
            if (!cursor->pprev) break;
            int64_t st = cursor->GetBlockTime() - cursor->pprev->GetBlockTime();
            solveTimes.push_back(st);
            cursor = cursor->pprev;
        }
        std::sort(solveTimes.begin(), solveTimes.end());
        rollingSolveTime = solveTimes[solveTimes.size() / 2];
        LogPrintf("🌀 DGW3-NOVA Rolling median solve time = %ds\n", rollingSolveTime);
    }

    // Trigger emergency logic BEFORE clamping
    bool triggered = v9 ? (actualSolveTime < 2 * minSolveTime && unclampedActualTimespan < targetTimespan / 6) : (actualSolveTime < minSolveTime || unclampedActualTimespan < targetTimespan / 6);

    if (triggered && nextHeight >= params.nextDifficultyFork3Height) {
        LogPrintf("🚨 [DGW3%s] Emergency/min solve triggered. Solve=%ds Timespan=%ds\n",
                v9 ? "-NOVA" : "", actualSolveTime, unclampedActualTimespan);
        actualTimespan = std::min(actualTimespan, std::min(emergencyClamp, minSolveClamp));
    }

    // Height-aware clamp normally after emergency trigger check
    if (v9) {
        if (!triggered) {
            if (actualTimespan < minTimespanClamp) actualTimespan = minTimespanClamp;
            if (actualTimespan > maxTimespanClamp) actualTimespan = maxTimespanClamp;
        } else {
            LogPrintf("🛡️ DGW3-NOVA Emergency trigger at height %d: skipping normal clamps\n", nextHeight);
        }
    } else {
        if (actualTimespan < minTimespanClamp) actualTimespan = minTimespanClamp;
        if (actualTimespan > maxTimespanClamp) actualTimespan = maxTimespanClamp;
    }

    // Graceful decay logic
    double decayFactor = 1.0;
    if (nextHeight >= v9 && actualSolveTime > params.nPowTargetSpacing) {
        double multiplier = std::min(6.0, double(actualSolveTime) / params.nPowTargetSpacing);
        double decayExponent = 0.45;
        double decayLimit = 2.0;
        decayFactor = std::pow(multiplier, decayExponent);
        decayFactor = std::min(decayFactor, decayLimit);
        LogPrintf("📉 DGW3-NOVA graceful decay (v9) applied: factor=%.2f (solve=%ds)\n", decayFactor, actualSolveTime);
    } 

    // Median smoothing of pastDifficultyAverage (Fork 9)
    arith_uint256 difficultySmoothing = pastDifficultyAverage;
    if (v9) {
        std::vector<arith_uint256> pastDiffs;
        const CBlockIndex* cursor = pindexLast;
        for (int i = 0; i < std::min(nPastBlocks, 5); ++i) {
            if (!cursor->pprev) break;
            arith_uint256 prevDiff;
            prevDiff.SetCompact(cursor->nBits);
            pastDiffs.push_back(prevDiff);
            cursor = cursor->pprev;
        }
        std::sort(pastDiffs.begin(), pastDiffs.end());
        difficultySmoothing = pastDiffs[pastDiffs.size() / 2];
        LogPrintf("📊 DGW3-NOVA Difficulty median smoothing active\n");
    }

    // Final difficulty calculation with asymmetry
    arith_uint256 baseline = difficultySmoothing * actualTimespan / targetTimespan;
    arith_uint256 newDifficulty = baseline;

    if (nextHeight >= v9 && decayFactor > 1.0) {
        arith_uint256 diffToPrevious = baseline > difficultySmoothing ? (baseline - difficultySmoothing) : 0;
        newDifficulty = baseline - (diffToPrevious / decayFactor);
        LogPrintf("🪂 DGW3-NOVA decay-from-baseline: newDifficulty=%.8f\n", newDifficulty.getdouble());
    }

    arith_uint256 bnPowLimit = UintToArith256(GetPowLimitForHeight(nextHeight, params));

    if (nextHeight <= 1 && newDifficulty > bnPowLimit) {
        newDifficulty = bnPowLimit;
    }

    // Post-reactivation: cap the retarget result at the Yespower powLimit.
    // SHA256 miners always have diff >= 1 work (the check path clamps the
    // effective SHA256 target at the SHA256 powLimit); the wider Yespower
    // limit here just keeps the encoded nBits within a representable band
    // for any future fallback solution.
    if (IsPostSha256Fork(nextHeight, params)) {
        arith_uint256 yespowerCap = UintToArith256(params.powLimitYespower);
        if (newDifficulty > yespowerCap) newDifficulty = yespowerCap;
    }

    LogPrintf("⛏️ Retargeting at height=%d with DGW3-NOVA\n", pindexLast->nHeight);
    return newDifficulty.GetCompact();
}

unsigned int DarkGravityWave3(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    const int nPastBlocks = 24;
    int nextHeight = (pindexLast ? pindexLast->nHeight + 1 : 0);
    
    LogPrintf("💡 DGW3: nHeight=%d returning powLimit %s\n", nextHeight,
        IsPostSha256Fork(nextHeight, params) ? "SHA256 (post-fork)"
        : (nextHeight >= params.yespowerForkHeight ? "Yespower" : "SHA256"));
    arith_uint256 limit = UintToArith256(GetPowLimitForHeight(nextHeight, params));
    LogPrintf("💡 DGW3: powLimit used = %s\n", limit.ToString());
    if (nextHeight < nPastBlocks)
        return limit.GetCompact();

    const CBlockIndex* pindex = pindexLast;
    arith_uint256 pastDifficultyAverage;
    arith_uint256 pastDifficultyAveragePrev;

    int64_t actualTimespan = 0;
    int64_t lastBlockTime = 0;

    for (int i = 0; i < nPastBlocks; ++i) {
        if (!pindex)
            break;

        arith_uint256 currentDifficulty = arith_uint256().SetCompact(pindex->nBits);

        if (i == 0)
            pastDifficultyAverage = currentDifficulty;
        else
            pastDifficultyAverage = ((pastDifficultyAveragePrev * i) + currentDifficulty) / (i + 1);

        pastDifficultyAveragePrev = pastDifficultyAverage;

        if (lastBlockTime > 0)
            actualTimespan += lastBlockTime - pindex->GetBlockTime();

        lastBlockTime = pindex->GetBlockTime();
        pindex = pindex->pprev;
    }

    const int64_t targetTimespan = nPastBlocks * params.nPowTargetSpacing;

    if (actualTimespan < targetTimespan / 3)
        actualTimespan = targetTimespan / 3;
    if (actualTimespan > targetTimespan * 3)
        actualTimespan = targetTimespan * 3;

    arith_uint256 newDifficulty = pastDifficultyAverage * actualTimespan / targetTimespan;

    arith_uint256 bnPowLimit = UintToArith256(GetPowLimitForHeight(nextHeight, params));

    if (pindexLast->nHeight + 1 <= 5879 && newDifficulty > bnPowLimit) {
        newDifficulty = bnPowLimit;
    }

    // Post-reactivation: cap the retarget at the Yespower powLimit
    // (see matching comment in DarkGravityWave3Nova).
    if (IsPostSha256Fork(nextHeight, params)) {
        arith_uint256 yespowerCap = UintToArith256(params.powLimitYespower);
        if (newDifficulty > yespowerCap) newDifficulty = yespowerCap;
    }

    LogPrintf("⛏️ Retargeting at height=%d with DGW3\n", pindexLast->nHeight);

    return newDifficulty.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4)
        nActualTimespan = params.nPowTargetTimespan / 4;
    if (nActualTimespan > params.nPowTargetTimespan * 4)
        nActualTimespan = params.nPowTargetTimespan * 4;

    const int nextHeight = pindexLast->nHeight + 1;
    arith_uint256 bnPowLimit = UintToArith256(GetPowLimitForHeight(nextHeight, params));

    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;
    
    LogPrintf("CalculateNextWorkRequired: nBits=%08x, target=%s\n",
              bnNew.GetCompact(), bnNew.ToString());
    
    return bnNew.GetCompact();
}

unsigned int Lwma3(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    const int N = 60;
    const int64_t T = params.nPowTargetSpacing;
    const int64_t k = N * (N + 1) / 2;

    const int nextHeight = pindexLast->nHeight + 1;
    uint256 powLimit = GetPowLimitForHeight(nextHeight, params);

    arith_uint256 bnPowLimit = UintToArith256(powLimit);

    // Prevent division by zero at fork
    if (pindexLast->nHeight + 1 < params.nextDifficultyForkHeight + N) {
        LogPrintf("🧪 Not enough history for LWMA3, returning powLimit\n");
        return bnPowLimit.GetCompact();
    }

    arith_uint256 sumTarget;
    int64_t t = 0;

    const CBlockIndex* pindex = pindexLast;
    for (int i = 0; i < N; ++i) {
        if (!pindex->pprev) break;
        int64_t solvetime = pindex->GetBlockTime() - pindex->pprev->GetBlockTime();
        if (solvetime > 6 * T) solvetime = 6 * T;
        if (solvetime < -6 * T) solvetime = -6 * T;
        int weight = i + 1;
        t += solvetime * weight;
        sumTarget += arith_uint256().SetCompact(pindex->nBits) * weight;
        pindex = pindex->pprev;
    }

    if (t <= 0) {
        LogPrintf("⚠️ Bad LWMA3 t <= 0, fallback to powLimit\n");
        return bnPowLimit.GetCompact();
    }

    arith_uint256 nextTarget = sumTarget * T / (k * t);
    if (nextTarget > bnPowLimit)
        nextTarget = bnPowLimit;

    LogPrintf("⛏️ LWMA3: height=%d target=%s\n", pindexLast->nHeight + 1, nextTarget.ToString());
    return nextTarget.GetCompact();
}

bool CheckProofOfWorkWithHeight(uint256 hash, CBlockHeader block, unsigned int nBits, const Consensus::Params& params, int nHeight, int64_t prevBlockTime)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    LogPrintf("💡 CheckProofOfWorkWithHeight: nHeight=%d prevBlockTime=%lld\n", nHeight, (long long)prevBlockTime);
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    if (nHeight == 0 || hash == params.hashGenesisBlock) {
        LogPrintf("🧱 Skipping PoW check for genesis block\n");
        return true;
    }

    if (fNegative || fOverflow || bnTarget == 0) {
        LogPrintf("❌ Legacy block rejected: bad nBits or target too easy\n");
        return false;
    }

    // -----------------------------------------------------------------------
    // POST-REACTIVATION (height >= sha256ReactivationHeight): dual PoW.
    //
    //   SHA256 is always accepted. The effective SHA256 target is the
    //   block's encoded target clamped at the SHA256 powLimit so SHA256
    //   miners always have diff >= 1 work regardless of nBits.
    //
    //   Yespower is additionally accepted when the time-based emergency
    //   trigger is armed for this block:
    //       (block.nTime - prevBlock.nTime) > nPowEmergencyTimeout.
    //   The Yespower target is the block's encoded target and must fit
    //   inside the Yespower powLimit.
    // -----------------------------------------------------------------------
    if (IsPostSha256Fork(nHeight, params)) {
        const arith_uint256 sha256Limit   = UintToArith256(params.powLimit);
        const arith_uint256 yespowerLimit = UintToArith256(params.powLimitYespower);

        if (bnTarget > yespowerLimit) {
            LogPrintf("❌ Post-reactivation block rejected: target above yespower powLimit\n");
            return false;
        }

        const bool grace     = IsYespowerGraceActive(nHeight, params);
        const bool emergency = IsEmergencyArmed((int64_t)block.nTime, prevBlockTime, params);
        const bool yespowerAllowed = grace || emergency;
        LogPrintf("🔁 Dual-PoW @%d: SHA256 always-on%s%s (gap=%lds, threshold=%lds, graceEnds=%d)\n",
                  nHeight,
                  grace     ? " + Yespower (grace window)" : "",
                  (!grace && emergency) ? " + Yespower (emergency)" : "",
                  (long)(prevBlockTime < 0 ? -1 : (int64_t)block.nTime - prevBlockTime),
                  (long)params.nPowEmergencyTimeout,
                  params.sha256ReactivationHeight + params.nPowYespowerGraceBlocks);

        // ---- SHA256 path: always available post-fork ----
       // Use the block's encoded nBits target directly. This is the chain's
        // consensus difficulty for this height, set by DGW3-Nova.
        //
        // Earlier versions clamped the effective target DOWN to the SHA256
        // powLimit (Bitcoin-style ~0x00000000ffff...), reasoning that SHA256
        // miners should always face >=1 work. That clamp made post-fork
        // solo-mining impossible: nBits inherited from Yespower is much
        // looser than sha256Limit, so the clamp required ASIC-level SHA256
        // hashpower just to clear the very first block. DGW3-Nova's emergency
        // trigger + decay-from-baseline will ramp difficulty up to honest
        // SHA256 levels within ~10-30 blocks on its own; the clamp is both
        // unnecessary and harmful during the transition.
        //
        // The upper bound (bnTarget > yespowerLimit) is still enforced above,
        // so a block can't be artificially trivial beyond the chain's
        // declared minimum difficulty.
        (void)sha256Limit; // retained for potential future use
        if (UintToArith256(hash) <= bnTarget) {
            LogPrintf("📏 SHA256 hash <= target ✅\n");
            return true;
        }

        // ---- Yespower path: open during grace window, or armed via emergency timeout ----
        if (yespowerAllowed) {
            LogPrintf("🛟 Trying Yespower (%s)\n", grace ? "grace window" : "emergency fallback");
            return CheckYespower(block, bnTarget, nHeight);
        }

        LogPrintf("📏 SHA256 hash <= target ❌ (Yespower not allowed: no grace, no emergency)\n");
        return false;
    }

    // -----------------------------------------------------------------------
    // PRE-REACTIVATION: original Yespower path (historical chain).
    // -----------------------------------------------------------------------
    if (nHeight >= 1) {
        LogPrintf("⚡ Using Yespower at height %d\n", nHeight);
        if (nHeight == 1) {
            return true;
        }
        LogPrintf("🧮 Computed hash: %s\n", hash.ToString());
        LogPrintf("🎯 Target:        %s\n", bnTarget.ToString());
        LogPrintf("📏 Comparison:    hash <= target ? %s\n", (UintToArith256(hash) <= bnTarget) ? "✅ YES" : "❌ NO");
        return CheckYespower(block, bnTarget, nHeight);
    } else {
        LogPrintf("🔒 Using SHA256 at height %d\n", nHeight);
        uint256 b_hash = block.GetHash(); // SHA256
        return UintToArith256(b_hash) <= bnTarget;
    }
}

bool CheckProofOfWork(uint256 hash, const CBlockHeader& blockHeader, unsigned int nBits, const Consensus::Params& params, int nHeight, int64_t prevBlockTime)
{
    const char* algoTag = IsPostSha256Fork(nHeight, params)
                              ? "SHA256 (post-reactivation, Yespower fallback when stalled)"
                              : ((nHeight >= params.yespowerForkHeight) ? "Yespower" : "SHA256");
    LogPrintf("🚧 CheckPoW height=%d, using: %s\n", nHeight, algoTag);

    if (nHeight == 0) {
        LogPrintf("🧱 Skipping PoW check for genesis block\n");
        return true;
    }

    // Post-reactivation always goes through the dual-PoW path.
    if (IsPostSha256Fork(nHeight, params)) {
        return CheckProofOfWorkWithHeight(hash, blockHeader, nBits, params, nHeight, prevBlockTime);
    }

    if (nHeight >= params.yespowerForkHeight) {
        return CheckProofOfWorkWithHeight(hash, blockHeader, nBits, params, nHeight, prevBlockTime);
    }

    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;
    return UintToArith256(hash) <= bnTarget;
}
