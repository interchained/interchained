// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

/**
 * Tri-PoW algorithm tag (2 bits in CBlockHeader::nVersion).
 *
 * Bit allocation analysis (checked against this tree, 2026-11-07):
 * - BIP9/versionbits (src/versionbits.h, src/versionbits.cpp): the top 3
 *   bits of nVersion (mask 0xE0000000) must stay 001, and bits 0..28
 *   (VERSIONBITS_NUM_BITS == 29) are the versionbits signalling pool.
 *   Bits 29-30 are inside the top mask and can NOT carry the tag.
 * - Deployments actually present (Consensus::MAX_VERSION_BITS_DEPLOYMENTS
 *   == 2, set identically in all four networks in src/chainparams.cpp):
 *   DEPLOYMENT_TESTDUMMY uses bit 28, DEPLOYMENT_TAPROOT uses bit 2.
 *   DEPLOYMENT_SEGWIT is commented out and would use bit 1. The legacy
 *   VERSIONBITS_KAWPOW version constant (0x20000038, miner use commented
 *   out) occupies bits 3, 4 and 5.
 * - Bits 13 and 14 are used by NO deployment and NO legacy constant, and
 *   sit well clear of every used bit (1, 2, 3-5, 28), so the tag is placed
 *   there: shift 13, mask 0x00006000, tag value == PowAlgo enum value.
 *   Tag 0 (untagged, every pre-fork header) decodes as SHA256, so old
 *   headers need no migration. Tag value 3 is RESERVED: GetBlockPowAlgo
 *   maps it to SHA256 and validation must reject it separately if desired.
 *
 * CONSTRAINT this places on the future: bits 13 and 14 are PERMANENTLY
 * RESERVED for this tag. No future BIP9 deployment may ever be allocated
 * bit 13 or 14 (the usable BIP9 pool shrinks from 29 to 27 bits, and any
 * deployment allocator in chainparams must skip them), or miners would
 * corrupt the algo tag / be misread as signalling. Side effect: software
 * that does not know the tag may emit cosmetic "unknown versionbit 13/14"
 * warnings (the warning checker scans all 29 bits); there is no consensus
 * effect, because no deployment Condition() reads bits 13 or 14.
 */
enum class PowAlgo : int { SHA256 = 0, YESPOWER = 1, ETHASH = 2 };

static constexpr int POW_ALGO_TAG_SHIFT = 13;
static constexpr int32_t POW_ALGO_TAG_MASK = (0x3 << POW_ALGO_TAG_SHIFT); // 0x00006000

/** Decode the raw 2-bit tag stored in an nVersion value. */
inline int PowAlgoTagFromVersion(int32_t nVersion)
{
    return (nVersion & POW_ALGO_TAG_MASK) >> POW_ALGO_TAG_SHIFT;
}

/**
 * Which PoW algorithm a block uses.
 * At/after params.triPowForkHeight the nVersion tag bits decide
 * (untagged/0 -> SHA256). Before the fork, the era mapping applies:
 * height < yespowerForkHeight -> SHA256;
 * yespowerForkHeight <= height < sha256ReactivationHeight -> YESPOWER;
 * height >= sha256ReactivationHeight -> SHA256.
 */
PowAlgo GetBlockPowAlgo(const CBlockHeader& block, int nHeight, const Consensus::Params& params);

/** Clear and set the tag bits in block.nVersion, preserving every other
 *  bit (including all versionbits signalling bits and the top mask). */
void SetBlockPowAlgo(CBlockHeader& block, PowAlgo algo);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
/**
 * Check proof of work for a block.
 *
 * @param prevBlockTime  Timestamp (seconds) of the previous block. Used
 *                       post-reactivation to decide whether the Yespower
 *                       emergency fallback is armed for this block.
 *                       Pass -1 when unknown (reload/reindex/test paths);
 *                       in that case the fallback is permissively armed
 *                       so already-validated blocks reload cleanly.
 */
bool CheckProofOfWork(uint256 hash, const CBlockHeader& blockHeader, unsigned int nBits, const Consensus::Params& params, int nHeight, int64_t prevBlockTime = -1);
bool CheckProofOfWorkWithHeight(uint256 hash, CBlockHeader block, unsigned int nBits, const Consensus::Params&, int nHeight, int64_t prevBlockTime = -1);

#endif // BITCOIN_POW_H
