// Copyright (c) 2026 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for tri-PoW validation: SHA256 + Yespower + Ethash dispatch
// at consensus.triPowForkHeight, modelled on dual_pow_tests.cpp.
//
//   1. An Ethash-tagged block mined in-test (via the wrapper's
//      MineEthash, which records the winning nonce's mix hash)
//      validates post-fork at its own-track nBits.
//   2. The same header with a tampered mixHash is rejected.
//   3. The same header re-tagged to another algo is rejected on that
//      algo's track (cross-algo solutions do not transfer).
//   4. Post-fork, a Yespower-tagged block validates on its own track
//      with NO emergency arming and NO grace window — the headline
//      behaviour change from the dual-PoW model, where post-reactivation
//      Yespower was emergency/grace-only.
//   5. In [sha256ReactivationHeight, triPowForkHeight) the OLD rules are
//      unchanged: Yespower needs the emergency trigger, exactly as in
//      dual_pow_tests.
//   6. A single header sequence from height 1 through fork+2 validates
//      era-by-era: Yespower era, post-reactivation SHA256 era, then one
//      post-fork block of EACH algo.
//
// Difficulty choices (keep in-test mining cheap, cross-algo accidental
// passes negligible): the Ethash/Yespower/SHA256 test limits below give
// ~2^6 / ~2^1 / ~2^1 expected work per solution, so mining converges in
// a handful of hashes. A solution for one algo meeting another algo's
// target at THOSE limits would NOT be negligible (~2^-6), so the
// cross-algo case (3) instead checks the re-tagged header against a
// ~2^20-work target (target ~2^236): an accidental pass there has
// probability ~2^-20, and the test additionally bumps nNonce until the
// re-tagged header's Yespower hash provably misses that target, making
// the rejection deterministic rather than probabilistic.

#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <pow/ethash.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <arith_uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tri_pow_validation_tests, BasicTestingSetup)

namespace {

constexpr int YESPOWER_FORK = 10;
constexpr int REACTIVATION  = 20;
constexpr int TRI_FORK      = 30;

// Consensus copied from regtest (per the tri-PoW test spec), with the
// era heights compressed so tests can pick heights freely:
//   yespowerForkHeight = 10, sha256ReactivationHeight = 20,
//   triPowForkHeight = 30, grace disabled, emergency timeout 120s.
// powLimit (SHA256) stays at the regtest value (~2^255).
// powLimitYespower is raised to ~2^255 (dual_pow_tests precedent) and
// powLimitEthash to ~2^250, so in-test mining of every algo is fast;
// Ethash at these heights is epoch 0, the cheapest epoch.
Consensus::Params MakeTestConsensus(const ArgsManager& args)
{
    auto p = CreateChainParams(args, CBaseChainParams::REGTEST)->GetConsensus();
    p.yespowerForkHeight       = YESPOWER_FORK;
    p.sha256ReactivationHeight = REACTIVATION;
    p.triPowForkHeight         = TRI_FORK;
    p.nPowEmergencyTimeout     = 120;
    p.nPowYespowerGraceBlocks  = 0;
    p.powLimitYespower = uint256S(
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    p.powLimitEthash = uint256S(
        "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return p;
}

unsigned int BitsOf(const uint256& limit)
{
    return UintToArith256(limit).GetCompact();
}

arith_uint256 TargetOf(unsigned int nBits)
{
    arith_uint256 t;
    t.SetCompact(nBits);
    return t;
}

// ~2^236: the ~2^20-work target used for cross-algo rejection (case 3).
unsigned int HardBits()
{
    return BitsOf(uint256S(
        "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
}

CBlockHeader MakeHeader(unsigned int nBits, uint32_t nTime)
{
    CBlockHeader h;
    h.nVersion       = 1;
    h.hashPrevBlock  = uint256();
    h.hashMerkleRoot = uint256();
    h.nTime          = nTime;
    h.nBits          = nBits;
    h.nNonce         = 0;
    h.nNonce64       = 0;
    h.mixHash        = uint256();
    return h;
}

CBlockHeader MakeTaggedHeader(PowAlgo algo, unsigned int nBits, uint32_t nTime)
{
    CBlockHeader h = MakeHeader(nBits, nTime);
    SetBlockPowAlgo(h, algo);
    return h;
}

void MineSha256(CBlockHeader& h)
{
    const arith_uint256 target = TargetOf(h.nBits);
    while (UintToArith256(h.GetHash()) > target) ++h.nNonce;
}

// dual_pow_tests pattern: iterate nNonce until YespowerHash meets target.
void MineYespower(CBlockHeader& h, int height)
{
    const arith_uint256 target = TargetOf(h.nBits);
    while (UintToArith256(h.YespowerHash(height)) > target) ++h.nNonce;
}

// Yespower solution whose SHA256d hash FAILS the SHA256 target: the only
// way validation can accept it is via a Yespower path (cases 5 and 6).
void MineYespowerShaFails(CBlockHeader& h, int height,
                          const Consensus::Params& p)
{
    const arith_uint256 yTarget = TargetOf(h.nBits);
    const arith_uint256 sTarget = TargetOf(BitsOf(p.powLimit));
    while (UintToArith256(h.YespowerHash(height)) > yTarget ||
           UintToArith256(h.GetHash()) <= sTarget) {
        ++h.nNonce;
    }
}

// Ethash mining: delegate to the wrapper's MineEthash, which tries
// consecutive nNonce64 values AND records the winning nonce's mix hash
// in the header. (Iterating nonces against CheckEthash alone could
// never succeed: verification requires the recorded mixHash to match
// the computed one, and only the miner learns it.) The budget turns a
// broken MineEthash into a loud failure, not a hang.
// NOTE (integration): renamed from the lane's local MineEthash helper
// to MineEthashForTest to avoid overloading the wrapper function.
void MineEthashForTest(CBlockHeader& h, int height)
{
    const arith_uint256 target = TargetOf(h.nBits);
    BOOST_REQUIRE_MESSAGE(MineEthash(h, target, height, 100000),
        "ethash in-test mining exceeded nonce budget");
}

} // namespace

// ---------------------------------------------------------------------------
// 1. Ethash block mined in-test validates post-fork at its own nBits.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ethash_block_validates_postfork)
{
    const auto p = MakeTestConsensus(*m_node.args);
    const int height = TRI_FORK + 10;
    CBlockHeader hdr = MakeTaggedHeader(PowAlgo::ETHASH,
                                        BitsOf(p.powLimitEthash), 1'000'000);
    MineEthashForTest(hdr, height);

    BOOST_CHECK(GetBlockPowAlgo(hdr, height, p) == PowAlgo::ETHASH);
    BOOST_CHECK(CheckEthash(hdr, TargetOf(hdr.nBits), height));
    // Small gap to the previous block: no emergency/grace concept exists
    // post-fork, and none is needed on the Ethash track.
    BOOST_CHECK(CheckProofOfWorkWithHeight(hdr.GetHash(), hdr, hdr.nBits, p,
                                           height, hdr.nTime - 10));
    BOOST_CHECK(CheckProofOfWork(hdr.GetHash(), hdr, hdr.nBits, p,
                                 height, hdr.nTime - 10));
}

// ---------------------------------------------------------------------------
// 2. Tampered mixHash: the mined Ethash header no longer validates.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ethash_tampered_mixhash_rejected)
{
    const auto p = MakeTestConsensus(*m_node.args);
    const int height = TRI_FORK + 10;
    CBlockHeader hdr = MakeTaggedHeader(PowAlgo::ETHASH,
                                        BitsOf(p.powLimitEthash), 1'100'000);
    MineEthashForTest(hdr, height);
    BOOST_REQUIRE(CheckEthash(hdr, TargetOf(hdr.nBits), height));

    hdr.mixHash.begin()[0] ^= 0xff;

    BOOST_CHECK(!CheckEthash(hdr, TargetOf(hdr.nBits), height));
    BOOST_CHECK(!CheckProofOfWorkWithHeight(hdr.GetHash(), hdr, hdr.nBits, p,
                                            height, hdr.nTime - 10));
}

// ---------------------------------------------------------------------------
// 3. Cross-algo transfer fails: the Ethash solution, re-tagged Yespower,
//    does not validate on the Yespower track. Checked at a ~2^20-work
//    target (~2^236) so an accidental Yespower pass is ~2^-20 likely;
//    the nonce bump below then makes the rejection fully deterministic.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ethash_wrong_tag_rejected)
{
    const auto p = MakeTestConsensus(*m_node.args);
    const int height = TRI_FORK + 11;
    CBlockHeader hdr = MakeTaggedHeader(PowAlgo::ETHASH,
                                        BitsOf(p.powLimitEthash), 1'200'000);
    MineEthashForTest(hdr, height);
    BOOST_REQUIRE(CheckEthash(hdr, TargetOf(hdr.nBits), height));

    CBlockHeader retagged = hdr;
    SetBlockPowAlgo(retagged, PowAlgo::YESPOWER);
    retagged.nBits = HardBits();
    while (UintToArith256(retagged.YespowerHash(height)) <=
           TargetOf(retagged.nBits)) {
        ++retagged.nNonce; // expected: zero iterations (~2^-20 chance each)
    }

    BOOST_CHECK(GetBlockPowAlgo(retagged, height, p) == PowAlgo::YESPOWER);
    BOOST_CHECK(!CheckProofOfWorkWithHeight(retagged.GetHash(), retagged,
                                            retagged.nBits, p, height,
                                            retagged.nTime - 10));
}

// ---------------------------------------------------------------------------
// 4. HEADLINE CHANGE: post-fork Yespower validates on its own track with
//    a SMALL gap to the previous block — emergency NOT armed, grace = 0.
//    Under the dual-PoW model this exact shape was rejected (case 5).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(yespower_no_emergency_needed_postfork)
{
    const auto p = MakeTestConsensus(*m_node.args);
    const int height = TRI_FORK + 5;
    CBlockHeader hdr = MakeTaggedHeader(PowAlgo::YESPOWER,
                                        BitsOf(p.powLimitYespower), 1'300'000);
    MineYespower(hdr, height);

    BOOST_CHECK(GetBlockPowAlgo(hdr, height, p) == PowAlgo::YESPOWER);
    // Gap = 10s, far below the 120s nPowEmergencyTimeout.
    BOOST_CHECK(CheckProofOfWorkWithHeight(hdr.GetHash(), hdr, hdr.nBits, p,
                                           height, hdr.nTime - 10));
    BOOST_CHECK(CheckProofOfWork(hdr.GetHash(), hdr, hdr.nBits, p,
                                 height, hdr.nTime - 10));
}

// ---------------------------------------------------------------------------
// 5. Pre-fork rules unchanged in [sha256ReactivationHeight, triPowFork):
//    a Yespower-shaped block (SHA256d fails, Yespower meets target) is
//    REJECTED without emergency arming and ACCEPTED with it — mirroring
//    dual_pow_tests' post-reactivation cases.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(prefork_rules_unchanged)
{
    const auto p = MakeTestConsensus(*m_node.args);
    const int height = REACTIVATION + 5; // 25: dual-PoW era, pre-tri-PoW
    CBlockHeader hdr = MakeHeader(BitsOf(p.powLimitYespower), 1'400'000);
    MineYespowerShaFails(hdr, height, p);

    // Gap = 30s < 120s: fallback NOT armed -> rejected.
    BOOST_CHECK(!CheckProofOfWorkWithHeight(hdr.GetHash(), hdr, hdr.nBits, p,
                                            height, hdr.nTime - 30));
    // Gap = 3600s > 120s: emergency armed -> accepted via Yespower.
    BOOST_CHECK(CheckProofOfWorkWithHeight(hdr.GetHash(), hdr, hdr.nBits, p,
                                           height, hdr.nTime - 3600));
}

// ---------------------------------------------------------------------------
// 6. One chain, height 1..fork+2, validated block-by-block in sequence:
//    Yespower era (CheckProofOfWorkWithHeight's pre-reactivation branch
//    is the Yespower path for every height >= 2; height 1 short-circuits),
//    post-reactivation SHA256 era, then post-fork one block of EACH algo.
//    Proves historical-era validation and the fork transition together.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(sync_from_genesis_era_chain)
{
    const auto p = MakeTestConsensus(*m_node.args);
    const uint32_t t0 = 1'700'000'000;
    uint256 prevHash;               // null: height 1 has no parent
    int64_t prevTime = -1;

    for (int height = 1; height <= TRI_FORK + 2; ++height) {
        CBlockHeader hdr;
        uint32_t nTime = t0 + height * 600;
        if (height < REACTIVATION) {
            hdr = (height >= YESPOWER_FORK)
                ? MakeTaggedHeader(PowAlgo::YESPOWER,
                                   BitsOf(p.powLimitYespower), nTime)
                : MakeHeader(BitsOf(p.powLimitYespower), nTime);
            hdr.hashPrevBlock = prevHash;
            if (height > 1) MineYespower(hdr, height);
        } else if (height < TRI_FORK) {
            hdr = MakeHeader(BitsOf(p.powLimit), nTime);
            hdr.hashPrevBlock = prevHash;
            MineSha256(hdr);
        } else if (height == TRI_FORK) {
            hdr = MakeTaggedHeader(PowAlgo::SHA256, BitsOf(p.powLimit), nTime);
            hdr.hashPrevBlock = prevHash;
            MineSha256(hdr);
        } else if (height == TRI_FORK + 1) {
            // 10s after its parent: post-fork Yespower needs no emergency.
            nTime = (uint32_t)prevTime + 10;
            hdr = MakeTaggedHeader(PowAlgo::YESPOWER,
                                   BitsOf(p.powLimitYespower), nTime);
            hdr.hashPrevBlock = prevHash;
            MineYespower(hdr, height);
        } else {
            hdr = MakeTaggedHeader(PowAlgo::ETHASH,
                                   BitsOf(p.powLimitEthash), nTime);
            hdr.hashPrevBlock = prevHash;
            MineEthashForTest(hdr, height);
        }

        if (height >= TRI_FORK) {
            const PowAlgo want = (height == TRI_FORK)     ? PowAlgo::SHA256
                               : (height == TRI_FORK + 1) ? PowAlgo::YESPOWER
                                                          : PowAlgo::ETHASH;
            BOOST_CHECK(GetBlockPowAlgo(hdr, height, p) == want);
        }
        BOOST_CHECK_MESSAGE(
            CheckProofOfWorkWithHeight(hdr.GetHash(), hdr, hdr.nBits, p,
                                       height, prevTime),
            "chain block rejected at height " << height);

        prevHash = hdr.GetHash();
        prevTime = hdr.nTime;
    }
}

BOOST_AUTO_TEST_SUITE_END()
