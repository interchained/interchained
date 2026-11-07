// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <amount.h>
#include <limits>

static const int32_t VERSIONBITS_KAWPOW = 0x20000038;

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // DEPLOYMENT_SEGWIT,
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
    
    int min_activation_height;
    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    int64_t nNodeOpsBp   = 0;
    int64_t nGovernanceBp = 0; 
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    int nDGW3Height;
    uint256 powLimitYespower;
    int yespowerForkHeight;
    int sha256ForkHeight;
    /**
     * Height at which SHA256 becomes the primary PoW for this network.
     * Distinct from `sha256ForkHeight`, which is a separate, pre-existing
     * field left untouched.
     *
     * Pre-sha256ReactivationHeight: Yespower is the primary PoW.
     * At/after sha256ReactivationHeight: SHA256 is always accepted.
     *   Yespower is additionally accepted on a per-block basis when the
     *   time-based emergency trigger (see `nPowEmergencyTimeout`) is armed.
     *
     * Defaults to `std::numeric_limits<int>::max()` so any network that
     * does not explicitly set this field never activates the fork.
     */
    int sha256ReactivationHeight{std::numeric_limits<int>::max()};
    /**
     * Post-reactivation emergency-fallback threshold, in seconds.
     *
     * For a candidate block at height >= sha256ReactivationHeight, the
     * Yespower fallback is armed when
     *     (block.nTime - prevBlock.nTime) > nPowEmergencyTimeout.
     * When armed, a Yespower solution is accepted in addition to SHA256.
     * SHA256 is always accepted regardless of arming.
     *
     * 0 disables the fallback entirely (SHA256-only post-reactivation).
     */
    int64_t nPowEmergencyTimeout{0};
    /**
     * Transition grace window, in blocks.
     *
     * For the first `nPowYespowerGraceBlocks` blocks at and after
     * `sha256ReactivationHeight`, Yespower is accepted UNCONDITIONALLY
     * (no `nPowEmergencyTimeout` arming requirement). This lets miners
     * coordinate the algorithm handoff without the chain cliff-stalling
     * at the exact activation height. SHA256 is also accepted throughout
     * the grace window. After the window closes, Yespower reverts to
     * emergency-only via `nPowEmergencyTimeout`.
     *
     * 0 disables the grace window (strict emergency-only from height
     * `sha256ReactivationHeight` onward).
     */
    int nPowYespowerGraceBlocks{0};
    /**
     * Height at which tri-PoW becomes active for this network.
     *
     * Heights < triPowForkHeight validate under era rules (the
     * pre-existing Yespower / SHA256-reactivation rules above).
     * Heights >= triPowForkHeight are tri-PoW: SHA256, Yespower and
     * Ethash are all accepted, each validated against its own
     * per-algo difficulty track (see `powLimit`, `powLimitYespower`
     * and `powLimitEthash`).
     *
     * Defaults to `std::numeric_limits<int>::max()` so any network that
     * does not explicitly set this field never activates tri-PoW.
     */
    int triPowForkHeight{std::numeric_limits<int>::max()};
    /**
     * Minimum-difficulty ceiling (maximum target) for the Ethash
     * track of tri-PoW. Ethash blocks at heights >= triPowForkHeight
     * must satisfy this limit in addition to their per-algo
     * difficulty target. Networks that never activate tri-PoW leave
     * it null and never consult it.
     */
    uint256 powLimitEthash;
    int difficultyForkHeight;
    int nextDifficultyForkHeight;
    int nextDifficultyFork2Height;
    int nextDifficultyFork3Height;
    int nextDifficultyFork4Height;
    int nextDifficultyFork5Height;
    /** Block height up to which transaction fees are burned */
    int nFeeBurnEndHeight{0};
    /** Total amount of fees burned so far */
    mutable CAmount nFeesBurned{0};
    uint256 powLimitEasyBlocks;
    /* Block hash that is excepted from BIP16 enforcement */
    uint256 BIP16Exception;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Interchained Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
