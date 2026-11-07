// Copyright (c) 2026 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INTERCHAINED_ETHASH_H
#define INTERCHAINED_ETHASH_H

#include <stdint.h>
#include "uint256.h"
#include "arith_uint256.h"
#include "primitives/block.h"

/**
 * Core Ethash (hashimoto-light) verification, independent of CBlockHeader.
 *
 * @param inputHash   Ethash input hash: SHA256d of the block header
 *                    serialized WITHOUT the Ethash extra fields
 *                    (nNonce64 / mixHash). See CheckEthash().
 * @param nonce       The 64-bit Ethash nonce (CBlockHeader::nNonce64).
 * @param mixHash     The mix hash carried by the block; the hashimoto-light
 *                    result's mix hash must match it exactly.
 * @param bnTarget    The target (from nBits); the final hash, read as a
 *                    big-endian 256-bit number as in Ethash, must be <= it.
 * @param blockNumber The block height; the Ethash epoch is
 *                    blockNumber / 30000 (ETHASH_EPOCH_LENGTH).
 * @return true iff the mix hash matches and final hash <= bnTarget.
 *
 * uint256 values cross the Ethash boundary in display (big-endian) byte
 * order: this function reverses uint256's internal little-endian bytes on
 * the way in and out, matching the chfast/ethash test-vector encoding.
 */
bool CheckEthashHash(const uint256& inputHash, uint64_t nonce,
                     const uint256& mixHash, const arith_uint256& bnTarget,
                     uint64_t blockNumber);

/**
 * Verify an Ethash-tagged block header.
 *
 * The input hash is SHA256d over ONLY the six standard header fields
 * (nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce),
 * serialized explicitly field-by-field, so the post-fork Ethash extra
 * fields (nNonce64, mixHash) never enter it — regardless of how the
 * header's own SerializationOp treats them.
 *
 * NOTE (signature): unlike the task sketch's 2-argument form, this takes
 * the block height (mirroring CheckYespower in pow/yespower.h, whose
 * caller CheckProofOfWorkWithHeight already has nHeight): the Ethash
 * epoch is derived from the height and cannot be recovered from the
 * header alone.
 *
 * NOTE (integration): this references CBlockHeader::nNonce64 and
 * CBlockHeader::mixHash, added by the block-header lane; it compiles
 * only once that lane is integrated.
 */
bool CheckEthash(const CBlockHeader& block, const arith_uint256& bnTarget, int height);

/**
 * Solve an Ethash-tagged header (mining).
 *
 * Tries up to maxTries consecutive nonces starting at block.nNonce64.
 * On success, block.nNonce64 holds the winning nonce and block.mixHash
 * holds the mix hash hashimoto-light computed for it (CheckEthash
 * requires the recorded mix hash to match, so a miner MUST set it —
 * iterating nonces against CheckEthash alone can never succeed).
 * On failure, block.nNonce64 is advanced past the tried range and
 * block.mixHash is untouched. Returns true iff solved.
 */
bool MineEthash(CBlockHeader& block, const arith_uint256& bnTarget, int height, uint64_t maxTries);

#endif // INTERCHAINED_ETHASH_H
