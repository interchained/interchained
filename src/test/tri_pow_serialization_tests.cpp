// Copyright (c) 2026 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the tri-PoW (SHA256 + Yespower + Ethash) algorithm tag
// and the Ethash-extended block-header serialization. These tests do NOT
// mine or check proof-of-work — they verify, against the fixed tri-PoW
// APIs in pow.h / CBlockHeader:
//
//   1. SetBlockPowAlgo / GetBlockPowAlgo round-trip for every algorithm
//      through SER_NETWORK serialization, with all standard header
//      fields preserved.
//   2. The Ethash-only extension fields (nNonce64, mixHash) round-trip
//      exactly, and are serialized only for Ethash-tagged headers.
//   3. Legacy wire size is unchanged: untagged, SHA256-tagged and
//      Yespower-tagged headers are exactly 80 bytes; an Ethash-tagged
//      header is 80 + 8 (nNonce64) + 32 (mixHash) = 120 bytes.
//   4. The algorithm tag coexists with ordinary nVersion bits (e.g. a
//      BIP9-style bit 2): tagging, re-tagging and serialization leave
//      the non-tag bits intact.
//   5. Era classification in GetBlockPowAlgo: before triPowForkHeight
//      an untagged header's algorithm is decided purely by height
//      (SHA256 -> Yespower -> SHA256 eras); at/after the fork the tag
//      rules apply and an untagged header classifies as SHA256.
//
// Consensus params follow dual_pow_tests.cpp's pattern: copy a real
// network's Consensus::Params (here regtest, whose tri-PoW fork is
// active from ~genesis) and mutate only the fork heights on the copy.

#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <version.h>

#include <array>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tri_pow_serialization_tests, BasicTestingSetup)

namespace {

// Regtest consensus with the tri-PoW fork pinned active from ~genesis
// (height 1), so the tag rules govern classification at the heights
// used by the round-trip tests below regardless of the exact regtest
// value shipped in chainparams. The pre-tri-PoW era heights are also
// pinned so no indeterminate regtest field is ever consulted.
Consensus::Params MakeRegtestParams(const ArgsManager& args)
{
    auto p = CreateChainParams(args, CBaseChainParams::REGTEST)->GetConsensus();
    p.yespowerForkHeight       = 1;
    p.sha256ReactivationHeight = 1;
    p.triPowForkHeight         = 1;
    return p;
}

// A header with distinctive, easily recognised values in every standard
// field, so a round-trip mix-up between fields cannot pass unnoticed.
// Starts untagged (no SetBlockPowAlgo call) with default Ethash fields.
CBlockHeader MakeDistinctHeader()
{
    CBlockHeader h;
    h.nVersion       = 1;
    h.hashPrevBlock  = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    h.hashMerkleRoot = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    h.nTime          = 1231006505;
    h.nBits          = 0x1d00ffff;
    h.nNonce         = 0xa5a5a5a5;
    return h;
}

// Serialize with SER_NETWORK and deserialize back; optionally report
// the serialized size in bytes.
CBlockHeader RoundTrip(const CBlockHeader& in, size_t* serialized_size = nullptr)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << in;
    if (serialized_size != nullptr) {
        *serialized_size = ss.size();
    }
    CBlockHeader out;
    ss >> out;
    return out;
}

void CheckStandardFieldsEqual(const CBlockHeader& expected, const CBlockHeader& actual)
{
    BOOST_CHECK_EQUAL(actual.nVersion, expected.nVersion);
    BOOST_CHECK(actual.hashPrevBlock == expected.hashPrevBlock);
    BOOST_CHECK(actual.hashMerkleRoot == expected.hashMerkleRoot);
    BOOST_CHECK_EQUAL(actual.nTime, expected.nTime);
    BOOST_CHECK_EQUAL(actual.nBits, expected.nBits);
    BOOST_CHECK_EQUAL(actual.nNonce, expected.nNonce);
}

constexpr std::array<PowAlgo, 3> AllAlgos{PowAlgo::SHA256, PowAlgo::YESPOWER, PowAlgo::ETHASH};

} // namespace

// ---------------------------------------------------------------------------
// 1. For each algorithm: tag a header, serialize, deserialize, and the
//    decoded header must classify as that algorithm (at the tri-PoW fork
//    height, under regtest-like params) with every standard field equal
//    to the tagged original.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(tag_roundtrip_each_algo)
{
    const auto params = MakeRegtestParams(*m_node.args);
    const int fork_height = params.triPowForkHeight;

    for (PowAlgo algo : AllAlgos) {
        CBlockHeader hdr = MakeDistinctHeader();
        SetBlockPowAlgo(hdr, algo);

        const CBlockHeader decoded = RoundTrip(hdr);

        BOOST_CHECK(GetBlockPowAlgo(decoded, fork_height, params) == algo);
        CheckStandardFieldsEqual(hdr, decoded);
    }
}

// ---------------------------------------------------------------------------
// 2. An Ethash-tagged header's extension fields survive the round-trip
//    bit-for-bit: nNonce64 (8 bytes) and mixHash (32 bytes).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ethash_extra_fields_roundtrip)
{
    const auto params = MakeRegtestParams(*m_node.args);

    CBlockHeader hdr = MakeDistinctHeader();
    SetBlockPowAlgo(hdr, PowAlgo::ETHASH);
    hdr.nNonce64 = 0xDEADBEEF12345678ULL;
    hdr.mixHash  = uint256S("3333333333333333333333333333333333333333333333333333333333333333");

    const CBlockHeader decoded = RoundTrip(hdr);

    BOOST_CHECK(GetBlockPowAlgo(decoded, params.triPowForkHeight, params) == PowAlgo::ETHASH);
    CheckStandardFieldsEqual(hdr, decoded);
    BOOST_CHECK_EQUAL(decoded.nNonce64, 0xDEADBEEF12345678ULL);
    BOOST_CHECK(decoded.mixHash == hdr.mixHash);
    BOOST_CHECK(!decoded.mixHash.IsNull());
}

// ---------------------------------------------------------------------------
// 3. Wire-size invariant: only Ethash-tagged headers grow. Untagged,
//    SHA256-tagged and Yespower-tagged headers stay at the legacy
//    80 bytes; Ethash-tagged is 80 + 8 + 32 = 120 bytes.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(legacy_size_unchanged)
{
    size_t size = 0;

    const CBlockHeader untagged = MakeDistinctHeader();
    RoundTrip(untagged, &size);
    BOOST_CHECK_EQUAL(size, 80U);

    for (PowAlgo algo : {PowAlgo::SHA256, PowAlgo::YESPOWER}) {
        CBlockHeader hdr = MakeDistinctHeader();
        SetBlockPowAlgo(hdr, algo);
        RoundTrip(hdr, &size);
        BOOST_CHECK_EQUAL(size, 80U);
    }

    CBlockHeader ethash = MakeDistinctHeader();
    SetBlockPowAlgo(ethash, PowAlgo::ETHASH);
    ethash.nNonce64 = 0xDEADBEEF12345678ULL;
    ethash.mixHash  = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    RoundTrip(ethash, &size);
    BOOST_CHECK_EQUAL(size, 120U);
}

// ---------------------------------------------------------------------------
// 4. The tag must not clobber ordinary nVersion bits. A BIP9-style bit 2
//    set before tagging survives tagging with each algorithm, a full
//    serialization round-trip, and switching the tag twice.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(tag_preserves_versionbits)
{
    const auto params = MakeRegtestParams(*m_node.args);
    constexpr int32_t kBit2 = 1 << 2;

    for (PowAlgo algo : AllAlgos) {
        CBlockHeader hdr = MakeDistinctHeader();
        hdr.nVersion |= kBit2;
        SetBlockPowAlgo(hdr, algo);
        BOOST_CHECK(hdr.nVersion & kBit2);

        const CBlockHeader decoded = RoundTrip(hdr);
        BOOST_CHECK(decoded.nVersion & kBit2);
        BOOST_CHECK(GetBlockPowAlgo(decoded, params.triPowForkHeight, params) == algo);
    }

    // Switching algorithms twice leaves the non-tag bits intact and the
    // final tag is the last one set (no stale tag bits).
    CBlockHeader hdr = MakeDistinctHeader();
    hdr.nVersion |= kBit2;
    SetBlockPowAlgo(hdr, PowAlgo::SHA256);
    BOOST_CHECK(hdr.nVersion & kBit2);
    SetBlockPowAlgo(hdr, PowAlgo::ETHASH);
    BOOST_CHECK(hdr.nVersion & kBit2);
    BOOST_CHECK(GetBlockPowAlgo(hdr, params.triPowForkHeight, params) == PowAlgo::ETHASH);
    SetBlockPowAlgo(hdr, PowAlgo::YESPOWER);
    BOOST_CHECK(hdr.nVersion & kBit2);
    BOOST_CHECK(GetBlockPowAlgo(hdr, params.triPowForkHeight, params) == PowAlgo::YESPOWER);

    const CBlockHeader decoded = RoundTrip(hdr);
    BOOST_CHECK(decoded.nVersion & kBit2);
    BOOST_CHECK(GetBlockPowAlgo(decoded, params.triPowForkHeight, params) == PowAlgo::YESPOWER);
}

// ---------------------------------------------------------------------------
// 5. Era classification with distinct fork heights (Yespower from 10,
//    SHA256 reactivation at 20, tri-PoW at 30) on a copied Params:
//    untagged headers classify by era alone before height 30; at/after
//    30 the tag rules apply and untagged defaults to SHA256.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(era_classification)
{
    auto params = MakeRegtestParams(*m_node.args);
    params.yespowerForkHeight       = 10;
    params.sha256ReactivationHeight = 20;
    params.triPowForkHeight         = 30;

    const CBlockHeader untagged = MakeDistinctHeader();
    BOOST_CHECK(GetBlockPowAlgo(untagged, 5, params) == PowAlgo::SHA256);
    BOOST_CHECK(GetBlockPowAlgo(untagged, 15, params) == PowAlgo::YESPOWER);
    BOOST_CHECK(GetBlockPowAlgo(untagged, 25, params) == PowAlgo::SHA256);

    // At/after the tri-PoW fork: untagged -> SHA256, tagged -> its tag.
    BOOST_CHECK(GetBlockPowAlgo(untagged, 30, params) == PowAlgo::SHA256);
    BOOST_CHECK(GetBlockPowAlgo(untagged, 100, params) == PowAlgo::SHA256);
    for (PowAlgo algo : AllAlgos) {
        CBlockHeader hdr = MakeDistinctHeader();
        SetBlockPowAlgo(hdr, algo);
        BOOST_CHECK(GetBlockPowAlgo(hdr, 30, params) == algo);
        BOOST_CHECK(GetBlockPowAlgo(hdr, 45, params) == algo);
    }
}

BOOST_AUTO_TEST_SUITE_END()
