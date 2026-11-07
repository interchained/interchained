// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <cstddef>

// The legacy header fields must keep occupying exactly the first 80 bytes
// of the object image: Yespower hashes that raw prefix (pow/yespower.cpp),
// and the Ethash input hash is defined over the same 80 bytes.
static_assert(offsetof(CBlockHeader, nNonce64) == 80,
              "Ethash extra fields must follow the 80-byte legacy header");

#include <pow.h> // PowAlgo, GetBlockPowAlgo / SetBlockPowAlgo (defined below)

#include <hash.h>
#include <tinyformat.h>
#include "pow/yespower.h"
// #include "crypto/kawpow/kawpow.h"

// uint256 CBlockHeader::GetKAWPOWHeaderHash(const uint256& kawpowSeed) const
// {
//     CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
//     ss << nVersion;
//     ss << hashPrevBlock;
//     ss << hashMerkleRoot;
//     ss << nTime;
//     ss << nBits;
//     ss << kawpowSeed; 
//     return ss.GetHash();
// }

// uint256 CBlockHeader::GetKAWPOWHash(int height) const {
//     return ::GetKAWPOWHash(*this, height);
// }

uint256 CBlockHeader::YespowerHash(int height) const {
    return ::YespowerHash(*this, height);
}

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

PowAlgo GetBlockPowAlgo(const CBlockHeader& block, int nHeight, const Consensus::Params& params)
{
    if (nHeight >= params.triPowForkHeight) {
        // Post-fork the nVersion tag bits are authoritative.
        switch (PowAlgoTagFromVersion(block.nVersion)) {
            case static_cast<int>(PowAlgo::YESPOWER): return PowAlgo::YESPOWER;
            case static_cast<int>(PowAlgo::ETHASH):   return PowAlgo::ETHASH;
            case static_cast<int>(PowAlgo::SHA256):
            default: // tag 3 is reserved; decode as SHA256 (see pow.h)
                return PowAlgo::SHA256;
        }
    }
    // Pre-fork era mapping (no tags existed on-chain).
    if (nHeight < params.yespowerForkHeight) {
        return PowAlgo::SHA256;
    }
    if (nHeight < params.sha256ReactivationHeight) {
        return PowAlgo::YESPOWER;
    }
    return PowAlgo::SHA256;
}

void SetBlockPowAlgo(CBlockHeader& block, PowAlgo algo)
{
    block.nVersion = (block.nVersion & ~POW_ALGO_TAG_MASK) |
                     ((static_cast<int32_t>(algo) << POW_ALGO_TAG_SHIFT) & POW_ALGO_TAG_MASK);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
