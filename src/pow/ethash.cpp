// Copyright (c) 2026 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// src/pow/ethash.cpp — Ethash (hashimoto-light) PoW verification via the
// vendored chfast/ethash library (src/crypto/ethash/, Apache-2.0).

#include "pow/ethash.h"

#include <hash.h>      // CHashWriter (SHA256d)
#include <serialize.h> // SER_GETHASH

#include <ethash/ethash.h>

#include <cstring>
#include <map>
#include <memory>
#include <mutex>

namespace {

//! uint256 stores bytes little-endian internally; Ethash hashes are
//! big-endian byte strings. Convert chain -> ethash representation.
ethash_hash256 ToEthashHash(const uint256& h)
{
    ethash_hash256 out;
    const unsigned char* p = h.begin();
    for (int i = 0; i < 32; ++i) out.bytes[i] = p[31 - i];
    return out;
}

//! Inverse of ToEthashHash.
uint256 FromEthashHash(const ethash_hash256& h)
{
    uint256 out;
    unsigned char* p = out.begin();
    for (int i = 0; i < 32; ++i) p[i] = h.bytes[31 - i];
    return out;
}

using EpochContextPtr =
    std::shared_ptr<ethash_epoch_context>;

//! Light contexts are ~17 MB (epoch 0) and grow slowly; keep a small
//! epoch-keyed cache. shared_ptr keeps a context alive while a caller
//! is hashing with it even if the cache is trimmed in the meantime.
std::shared_ptr<ethash_epoch_context> GetEpochContext(int epoch)
{
    static std::mutex cs;
    static std::map<int, EpochContextPtr> cache;
    std::lock_guard<std::mutex> lock(cs);
    auto it = cache.find(epoch);
    if (it != cache.end()) return it->second;
    EpochContextPtr ctx(ethash_create_epoch_context(epoch),
                        &ethash_destroy_epoch_context);
    if (!ctx) return nullptr;
    if (cache.size() >= 8) cache.clear(); // in-use contexts survive via shared_ptr
    cache.emplace(epoch, ctx);
    return ctx;
}

} // namespace

bool CheckEthashHash(const uint256& inputHash, uint64_t nonce,
                     const uint256& mixHash, const arith_uint256& bnTarget,
                     uint64_t blockNumber)
{
    const uint64_t epoch64 = blockNumber / ETHASH_EPOCH_LENGTH;
    if (epoch64 > ETHASH_MAX_EPOCH_NUMBER) return false;
    const int epoch = static_cast<int>(epoch64);

    auto ctx = GetEpochContext(epoch);
    if (!ctx) return false;

    const ethash_hash256 headerHash = ToEthashHash(inputHash);
    const ethash_result result = ethash_hash(ctx.get(), &headerHash, nonce);

    // The block's claimed mix hash must match the computed one.
    const ethash_hash256 expectedMix = ToEthashHash(mixHash);
    if (std::memcmp(result.mix_hash.bytes, expectedMix.bytes, 32) != 0)
        return false;

    // Final hash, as a big-endian Ethash number, must meet the target.
    return UintToArith256(FromEthashHash(result.final_hash)) <= bnTarget;
}

namespace {

// Ethash input hash: SHA256d of the header WITHOUT the Ethash extra
// fields. Serialize the six standard fields explicitly (rather than
// using the header's SerializationOp) so nNonce64/mixHash can never
// leak into the hash, whatever the tagged serialization does.
uint256 EthashInputHash(const CBlockHeader& block)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << block.nVersion;
    ss << block.hashPrevBlock;
    ss << block.hashMerkleRoot;
    ss << block.nTime;
    ss << block.nBits;
    ss << block.nNonce;
    return ss.GetHash();
}

} // namespace

bool CheckEthash(const CBlockHeader& block, const arith_uint256& bnTarget, int height)
{
    if (height < 0) return false;

    return CheckEthashHash(EthashInputHash(block), block.nNonce64, block.mixHash,
                           bnTarget, static_cast<uint64_t>(height));
}

bool MineEthash(CBlockHeader& block, const arith_uint256& bnTarget, int height, uint64_t maxTries)
{
    if (height < 0) return false;
    const uint64_t blockNumber = static_cast<uint64_t>(height);
    const uint64_t epoch64 = blockNumber / ETHASH_EPOCH_LENGTH;
    if (epoch64 > ETHASH_MAX_EPOCH_NUMBER) return false;
    const int epoch = static_cast<int>(epoch64);

    auto ctx = GetEpochContext(epoch);
    if (!ctx) return false;

    const ethash_hash256 headerHash = ToEthashHash(EthashInputHash(block));
    const uint64_t startNonce = block.nNonce64;
    for (uint64_t i = 0; i < maxTries; ++i) {
        const uint64_t nonce = startNonce + i;
        const ethash_result result = ethash_hash(ctx.get(), &headerHash, nonce);
        if (UintToArith256(FromEthashHash(result.final_hash)) <= bnTarget) {
            block.nNonce64 = nonce;
            block.mixHash = FromEthashHash(result.mix_hash);
            return true;
        }
    }
    block.nNonce64 = startNonce + maxTries;
    return false;
}
