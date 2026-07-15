// Copyright (c) 2026 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the SHA256 reactivation / dual-PoW dispatch logic added
// at consensus.sha256ReactivationHeight. These tests intentionally do NOT
// mine real PoW — they verify the *dispatch* decisions:
//
//   1. Pre-fork heights still route to Yespower.
//   2. Post-fork heights accept any header whose SHA256 hash satisfies
//      the encoded target.
//   3. Post-fork heights REJECT a header that fails SHA256 when the
//      time-gap to the previous block is below nPowEmergencyTimeout
//      (Yespower fallback NOT armed).
//   4. Post-fork heights enter the Yespower fallback path when the
//      time-gap exceeds nPowEmergencyTimeout, and the result is
//      independent of the pre-computed `hash` argument (the fallback
//      re-hashes the raw header itself).
//   5. An unknown previous timestamp arms the fallback during unordered
//      block-index loading.
//
// To keep tests deterministic and fast, we mutate a local copy of the
// mainnet Consensus::Params: we lower sha256ReactivationHeight, disable the
// grace window, and raise powLimitYespower to ~2^255. Fallback-path tests
// search a few nonces for a header below that easy Yespower target.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <arith_uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dual_pow_tests, BasicTestingSetup)

namespace {

// Build a Consensus::Params suitable for dispatch testing:
//   - sha256ReactivationHeight lowered to 1000 so we can pick heights freely.
//   - nPowEmergencyTimeout = 120 (matches mainnet).
//   - grace disabled so the emergency tests isolate timeout dispatch.
//   - powLimitYespower raised to ~2^255 for cheap Yespower test headers.
//   - powLimit (SHA256) left at mainnet value.
Consensus::Params MakeTestConsensus(const ArgsManager& args)
{
    auto p = CreateChainParams(args, CBaseChainParams::MAIN)->GetConsensus();
    p.sha256ReactivationHeight = 1000;
    p.nPowEmergencyTimeout     = 120;
    p.nPowYespowerGraceBlocks  = 0;
    // 2^255 - 1: approximately two hashes per valid test header.
    p.powLimitYespower = uint256S(
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return p;
}

// Construct an nBits encoding for a target equal to the SHA256 powLimit.
// Headers with hash <= this target satisfy the SHA256 path.
unsigned int EasySha256Bits(const Consensus::Params& p)
{
    return UintToArith256(p.powLimit).GetCompact();
}

unsigned int EasyYespowerBits(const Consensus::Params& p)
{
    return UintToArith256(p.powLimitYespower).GetCompact();
}

// Construct a dummy header. nTime is supplied by the caller because the
// emergency arming decision is purely time-based.
CBlockHeader MakeHeader(unsigned int nBits, uint32_t nTime)
{
    CBlockHeader h;
    h.nVersion       = 1;
    h.hashPrevBlock  = uint256();
    h.hashMerkleRoot = uint256();
    h.nTime          = nTime;
    h.nBits          = nBits;
    h.nNonce         = 0;
    return h;
}

// Find a header satisfying the fixture's easy Yespower target. This keeps
// fallback acceptance deterministic without weakening production logic.
CBlockHeader MakeYespowerHeader(const Consensus::Params& p, int height, uint32_t nTime)
{
    CBlockHeader h = MakeHeader(EasyYespowerBits(p), nTime);
    arith_uint256 target;
    target.SetCompact(h.nBits);
    while (UintToArith256(h.YespowerHash(height)) > target) {
        ++h.nNonce;
    }
    return h;
}

} // namespace


// ---------------------------------------------------------------------------
// Pre-fork heights: must still route through Yespower (legacy behavior).
// At nHeight == 1 the historical path short-circuits to true; we use that
// as a cheap signal that the pre-fork branch was taken.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(prefork_height_routes_to_yespower_path)
{
    const auto consensus = MakeTestConsensus(*m_node.args);
    const unsigned int nBits = EasySha256Bits(consensus);
    CBlockHeader hdr = MakeHeader(nBits, /*nTime=*/100);

    // nHeight == 1 triggers the historical short-circuit return-true in the
    // pre-fork branch. If we accidentally routed through the post-fork
    // SHA256 path instead, the all-zero hash below would still pass — so
    // we additionally verify a *failing* SHA256 hash also returns true,
    // which can ONLY happen in the pre-fork Yespower branch's height==1
    // short-circuit.
    uint256 impossible_for_sha256;
    impossible_for_sha256.SetHex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    BOOST_CHECK(CheckProofOfWork(impossible_for_sha256, hdr, nBits,
                                 consensus, /*nHeight=*/1,
                                 /*prevBlockTime=*/-1));
}


// ---------------------------------------------------------------------------
// Post-fork normal case: SHA256 hash satisfies SHA256 target → accepted.
// Gap to previous block is small (no emergency); fallback must NOT be
// needed for this to pass.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(postfork_sha256_hash_satisfies_target_accepted)
{
    const auto consensus = MakeTestConsensus(*m_node.args);
    const unsigned int nBits = EasySha256Bits(consensus);
    CBlockHeader hdr = MakeHeader(nBits, /*nTime=*/1'000'000);

    // Hash of 0x01 trivially satisfies the SHA256 powLimit target.
    uint256 easy_hash;
    easy_hash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");

    BOOST_CHECK(CheckProofOfWork(easy_hash, hdr, nBits, consensus,
                                 /*nHeight=*/2000,
                                 /*prevBlockTime=*/1'000'000 - 10));
}


// ---------------------------------------------------------------------------
// Post-fork rejection: SHA256 hash fails AND gap < nPowEmergencyTimeout.
// Emergency fallback is NOT armed → CheckProofOfWork must return false
// without ever invoking Yespower.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(postfork_failing_sha256_short_gap_rejected)
{
    const auto consensus = MakeTestConsensus(*m_node.args);
    const unsigned int nBits = EasySha256Bits(consensus);
    CBlockHeader hdr = MakeHeader(nBits, /*nTime=*/2'000'000);

    uint256 fail_sha256;
    fail_sha256.SetHex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    // Gap = 30s, well below the 120s emergency threshold.
    BOOST_CHECK(!CheckProofOfWork(fail_sha256, hdr, nBits, consensus,
                                  /*nHeight=*/2000,
                                  /*prevBlockTime=*/2'000'000 - 30));
}


// ---------------------------------------------------------------------------
// Post-fork rejection at exactly the emergency boundary.
// The arming condition is STRICTLY greater than nPowEmergencyTimeout
// (gap > 120), so a gap of exactly 120s must NOT arm the fallback.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(postfork_emergency_boundary_strict_inequality)
{
    const auto consensus = MakeTestConsensus(*m_node.args);
    const unsigned int nBits = EasySha256Bits(consensus);
    CBlockHeader hdr = MakeHeader(nBits, /*nTime=*/3'000'000);

    uint256 fail_sha256;
    fail_sha256.SetHex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    // Gap exactly == threshold → fallback NOT armed → must reject.
    BOOST_CHECK(!CheckProofOfWork(
        fail_sha256, hdr, nBits, consensus, /*nHeight=*/2000,
        /*prevBlockTime=*/(int64_t)hdr.nTime - consensus.nPowEmergencyTimeout));
}


// ---------------------------------------------------------------------------
// Post-fork Yespower fallback path: SHA256 hash fails AND gap > timeout.
// We raise powLimitYespower to ~2^255 in the test consensus so the
// fallback's internal yespower comparison always succeeds, isolating the
// dispatch decision: when armed, control reaches CheckYespower regardless
// of the pre-computed `hash` parameter.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(postfork_emergency_armed_reaches_yespower_fallback)
{
    const auto consensus = MakeTestConsensus(*m_node.args);
    CBlockHeader hdr = MakeYespowerHeader(consensus, /*height=*/2000,
                                          /*nTime=*/4'000'000);

    // A SHA256-failing hash — the only way this test can pass is if
    // the Yespower fallback is reached.
    uint256 fail_sha256;
    fail_sha256.SetHex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    // Gap = 3600s, far above 120s threshold → fallback armed.
    BOOST_CHECK(CheckProofOfWork(fail_sha256, hdr, hdr.nBits, consensus,
                                 /*nHeight=*/2000,
                                 /*prevBlockTime=*/4'000'000 - 3600));
}


// ---------------------------------------------------------------------------
// Critical invariant: the Yespower fallback ignores the `hash` argument
// entirely. We call the same header twice — once with an "easy" SHA256
// hash and once with a SHA256-failing hash — under emergency conditions.
// Both must return the same result because the fallback re-hashes the
// raw header internally.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(postfork_fallback_ignores_precomputed_hash)
{
    const auto consensus = MakeTestConsensus(*m_node.args);
    CBlockHeader hdr = MakeYespowerHeader(consensus, /*height=*/2000,
                                          /*nTime=*/5'000'000);

    uint256 easy;
    easy.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    uint256 hard;
    hard.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    const int64_t prev = 5'000'000 - 3600; // gap > 120s → fallback armed

    const bool r_easy = CheckProofOfWork(easy, hdr, hdr.nBits, consensus,
                                         /*nHeight=*/2000, prev);
    const bool r_hard = CheckProofOfWork(hard, hdr, hdr.nBits, consensus,
                                         /*nHeight=*/2000, prev);

    // Easy hash trivially passes SHA256 (returns true without entering
    // fallback). Hard hash forces the fallback path. The header was solved
    // against the fixture's easy Yespower target, so both return true and
    // prove fallback does not depend on the precomputed SHA256 hash.
    BOOST_CHECK(r_easy);
    BOOST_CHECK(r_hard);
}


// ---------------------------------------------------------------------------
// prevBlockTime == -1 (sentinel) is permissive: emergency IS armed when
// the previous timestamp is unavailable during unordered block-index load.
// This lets an already-validated historical Yespower fallback block be
// reloaded from disk instead of being rejected solely due to load order.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(postfork_sentinel_prev_time_arms_emergency)
{
    const auto consensus = MakeTestConsensus(*m_node.args);
    CBlockHeader hdr = MakeYespowerHeader(consensus, /*height=*/2000,
                                          /*nTime=*/6'000'000);

    uint256 fail_sha256;
    fail_sha256.SetHex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    // With prevBlockTime == -1 the emergency check must arm. The failing
    // SHA256 hash therefore reaches the deterministic Yespower fallback,
    // which succeeds under this fixture's permissive Yespower target.
    BOOST_CHECK(CheckProofOfWork(fail_sha256, hdr, hdr.nBits, consensus,
                                 /*nHeight=*/2000,
                                 /*prevBlockTime=*/-1));
}

BOOST_AUTO_TEST_SUITE_END()
