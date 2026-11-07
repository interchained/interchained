// Copyright (c) 2026 The Interchained Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Retarget-isolation tests for tri-PoW (SHA256 + Yespower + Ethash,
// activating at consensus.triPowForkHeight). Post-fork,
// GetNextWorkRequired runs DGW3-NOVA over the candidate algo's OWN
// ancestors only, with per-algo target spacing nPowTargetSpacing * 3
// and the result clamped at that algo's own powLimit.
//
// These tests assert the consensus-critical *properties* of that
// design -- isolation between tracks, bootstrap at the algo powLimit,
// and seeding from era-classified history -- rather than exact DGW
// output values, whose precise numbers depend on DGW3-NOVA clamp /
// smoothing details that are not the guarantee under test. Where a
// direction is asserted (test 3), it follows from the DGW formula
// itself (target scales with the same-algo timespan), not from a
// magic number.
//
// Spec APIs coded against (implemented by the other tri-PoW lanes):
//   * pow.h: enum class PowAlgo : int { SHA256=0, YESPOWER=1, ETHASH=2 };
//     PowAlgo GetBlockPowAlgo(const CBlockHeader&, int, const Consensus::Params&);
//     void SetBlockPowAlgo(CBlockHeader&, PowAlgo);
//   * Consensus::Params: int triPowForkHeight; uint256 powLimitEthash;
//   * GetNextWorkRequired selects the algo track from the candidate
//     header's tag; CBlockIndex ancestors classify by their stored
//     nVersion tag (post-fork) or by era (pre-fork).

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <arith_uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <deque>
#include <limits>

namespace {

struct TriPowRetargetSetup : public BasicTestingSetup {
    TriPowRetargetSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {}
};

constexpr int64_t kStartTime = 1'000'000;
constexpr int64_t kSpacing = 60;   //!< nPowTargetSpacing; per-algo = 180s
constexpr int64_t kAlgoSpacing = 3 * kSpacing;

// Test consensus copied from regtest, then pinned:
//   [0,yesFork) SHA256 era, [yesFork,react) Yespower era,
//   [react,triFork) post-reactivation SHA256 era, [triFork,...) tri-PoW.
// The three powLimits are DISTINCT magnitudes so the tracks are
// distinguishable. The DGW fork heights that would shrink the window
// to 12 (fork5) or arm the emergency clamp (fork3) are pushed to
// INT_MAX, giving the plain 24-sample DGW3-NOVA window these tests
// are written against.
Consensus::Params MakeParams(const ArgsManager& args,
                             int yesFork = 10, int react = 30, int triFork = 50)
{
    auto p = CreateChainParams(args, CBaseChainParams::REGTEST)->GetConsensus();
    p.yespowerForkHeight = yesFork;
    p.sha256ReactivationHeight = react;
    p.triPowForkHeight = triFork;
    p.powLimit = uint256S(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    p.powLimitYespower = uint256S(
        "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    p.powLimitEthash = uint256S(
        "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    p.nPowTargetSpacing = kSpacing;
    p.nPowTargetTimespan = 12 * 60 * 60;
    p.nPowEmergencyTimeout = 0;
    p.nPowYespowerGraceBlocks = 0;
    p.fPowAllowMinDifficultyBlocks = false;
    p.fPowNoRetargeting = false;
    p.nextDifficultyFork3Height = std::numeric_limits<int>::max();
    p.nextDifficultyFork5Height = std::numeric_limits<int>::max();
    return p;
}

unsigned int BitsOf(const uint256& limit)
{
    return UintToArith256(limit).GetCompact();
}

// Compact nBits for limit/divisor (a distinctive sub-limit seed value).
unsigned int BitsOfDivided(const uint256& limit, int64_t divisor)
{
    arith_uint256 t = UintToArith256(limit);
    t /= divisor;
    return t.GetCompact();
}

arith_uint256 TargetOf(unsigned int nBits)
{
    arith_uint256 t;
    t.SetCompact(nBits);
    return t;
}

CBlockHeader MakeTaggedHeader(PowAlgo algo, unsigned int nBits, uint32_t nTime)
{
    CBlockHeader h;
    h.nVersion = 1;
    h.hashPrevBlock = uint256();
    h.hashMerkleRoot = uint256();
    h.nTime = nTime;
    h.nBits = nBits;
    h.nNonce = 0;
    SetBlockPowAlgo(h, algo);
    return h;
}

// A chain of CBlockIndex objects linked by pprev (dual_pow_tests has
// no chain builder, so chains are constructed manually here, as the
// task specifies: pprev / nHeight / nTime / nBits / nVersion, the
// version carrying the algo tag via SetBlockPowAlgo on a temp header).
// std::deque keeps element addresses stable across appends.
struct FakeChain {
    std::deque<CBlockIndex> blocks;
    std::deque<uint256> hashes;

    const CBlockIndex* Tip() const { return blocks.empty() ? nullptr : &blocks.back(); }
    int Height() const { return blocks.empty() ? -1 : blocks.back().nHeight; }

    void Append(int32_t nVersion, unsigned int nBits, uint32_t nTime)
    {
        CBlockHeader hdr;
        hdr.nVersion = nVersion;
        hdr.nTime = nTime;
        hdr.nBits = nBits;
        hashes.push_back(hdr.GetHash());
        CBlockIndex idx;
        idx.nVersion = nVersion;
        idx.nTime = nTime;
        idx.nBits = nBits;
        idx.nHeight = static_cast<int>(blocks.size());
        idx.pprev = blocks.empty() ? nullptr : &blocks.back();
        idx.phashBlock = &hashes.back();
        blocks.push_back(idx);
        blocks.back().BuildSkip();
    }

    // Append one block whose version tag is `algo` (post-fork blocks).
    void AppendTagged(PowAlgo algo, unsigned int nBits, uint32_t nTime)
    {
        Append(MakeTaggedHeader(algo, nBits, nTime).nVersion, nBits, nTime);
    }
};

// Pre-fork filler for heights [0, triFork): untagged (nVersion 1), so
// ancestors classify by era. nBits/time are supplied per height by the
// caller so histories can be made distinctive.
template <typename F>
void AppendPreFork(FakeChain& chain, const Consensus::Params& p, F&& fn)
{
    uint32_t t = static_cast<uint32_t>(kStartTime);
    for (int h = 0; h < p.triPowForkHeight; ++h) {
        unsigned int nBits;
        int64_t dt;
        fn(h, nBits, dt);
        if (h > 0) t += static_cast<uint32_t>(dt);
        chain.Append(/*nVersion=*/1, nBits, t);
    }
}

// Next nBits on `algo`'s track; the tagged candidate header selects it.
unsigned int NextBits(const FakeChain& chain, PowAlgo algo, const Consensus::Params& p)
{
    CBlockHeader candidate = MakeTaggedHeader(algo, /*nBits=*/0,
        static_cast<uint32_t>(chain.Tip()->nTime + kAlgoSpacing));
    return GetNextWorkRequired(chain.Tip(), &candidate, p);
}

// Chain for isolation tests 1-2: pre-fork filler where every block of
// an era carries that era algo's seed nBits (powLimit/4) on a steady
// 180s grid, then 8 post-fork blocks of `track` (same seed, 180s
// apart). If `withExtra`, 20 fast (10s-offset) blocks of `extra` are
// interleaved between the post-fork track blocks; the track blocks'
// (nBits, nTime) sequence is bit-for-bit identical either way, so any
// change in the track's next nBits can only come from cross-algo
// leakage in the retarget walk.
FakeChain BuildIsolationChain(const Consensus::Params& p, PowAlgo track,
                              PowAlgo extra, bool withExtra)
{
    const unsigned int shaSeed = BitsOfDivided(p.powLimit, 4);
    const unsigned int yesSeed = BitsOfDivided(p.powLimitYespower, 4);
    const unsigned int ethSeed = BitsOfDivided(p.powLimitEthash, 4);
    auto seedFor = [&](PowAlgo a) {
        return a == PowAlgo::SHA256 ? shaSeed : a == PowAlgo::YESPOWER ? yesSeed : ethSeed;
    };

    FakeChain chain;
    AppendPreFork(chain, p, [&](int h, unsigned int& nBits, int64_t& dt) {
        dt = kAlgoSpacing;
        nBits = (h >= p.yespowerForkHeight && h < p.sha256ReactivationHeight)
                    ? yesSeed : shaSeed;
    });

    uint32_t t = static_cast<uint32_t>(kStartTime) +
                 static_cast<uint32_t>(p.triPowForkHeight * kAlgoSpacing);
    for (int i = 0; i < 8; ++i) {
        chain.AppendTagged(track, seedFor(track), t);
        if (withExtra) {
            const int nExtra = i < 4 ? 3 : 2; // 4*3 + 4*2 = 20 blocks
            for (int j = 0; j < nExtra; ++j) {
                chain.AppendTagged(extra, seedFor(extra),
                                   t + static_cast<uint32_t>(10 * (j + 1)));
            }
        }
        t += static_cast<uint32_t>(kAlgoSpacing);
    }
    return chain;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(tri_pow_retarget_tests, TriPowRetargetSetup)

// ---------------------------------------------------------------------------
// 1. Fast SHA256 blocks interleaved post-fork must not move the
//    Yespower track: its next nBits is computed from Yespower-classified
//    ancestors (era-seeded + tagged) only.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(sha_does_not_move_yespower)
{
    const auto p = MakeParams(*m_node.args);
    FakeChain a = BuildIsolationChain(p, PowAlgo::YESPOWER, PowAlgo::SHA256, false);
    FakeChain b = BuildIsolationChain(p, PowAlgo::YESPOWER, PowAlgo::SHA256, true);

    BOOST_REQUIRE_EQUAL(b.Height() - a.Height(), 20); // extra blocks really added
    const unsigned int next_a = NextBits(a, PowAlgo::YESPOWER, p);
    const unsigned int next_b = NextBits(b, PowAlgo::YESPOWER, p);
    BOOST_CHECK_EQUAL(next_a, next_b);
    // Non-degenerate: the result is a computed retarget, not the
    // powLimitYespower bootstrap/cap value.
    BOOST_CHECK(TargetOf(next_a) < UintToArith256(p.powLimitYespower));
    BOOST_CHECK(TargetOf(next_a) > TargetOf(BitsOfDivided(p.powLimitYespower, 4)));
}

// ---------------------------------------------------------------------------
// 2. Mirror image: fast Yespower blocks must not move the SHA256 track.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(yespower_does_not_move_sha)
{
    const auto p = MakeParams(*m_node.args);
    FakeChain a = BuildIsolationChain(p, PowAlgo::SHA256, PowAlgo::YESPOWER, false);
    FakeChain b = BuildIsolationChain(p, PowAlgo::SHA256, PowAlgo::YESPOWER, true);

    BOOST_REQUIRE_EQUAL(b.Height() - a.Height(), 20);
    const unsigned int next_a = NextBits(a, PowAlgo::SHA256, p);
    const unsigned int next_b = NextBits(b, PowAlgo::SHA256, p);
    BOOST_CHECK_EQUAL(next_a, next_b);
    BOOST_CHECK(TargetOf(next_a) < UintToArith256(p.powLimit));
}

// ---------------------------------------------------------------------------
// 3. A track DOES respond to its own blocks: post-fork Ethash blocks at
//    10s spacing (per-algo target 180s) make the next Ethash target
//    strictly smaller (harder) than the powLimitEthash seed, and
//    strictly smaller than the steady-180s result. Steady spacing keeps
//    the target in the seed's neighbourhood: DGW sums the 23 gaps
//    between 24 samples against a 24-block target timespan, so exact
//    equality is not expected -- direction and a wide band are
//    asserted instead of an exact value (see file header).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(same_algo_fast_blocks_raise_own_difficulty)
{
    const auto p = MakeParams(*m_node.args);
    const unsigned int ethSeed = BitsOf(p.powLimitEthash);

    auto build = [&](int64_t dt) {
        FakeChain chain;
        AppendPreFork(chain, p, [&](int, unsigned int& nBits, int64_t& d) {
            nBits = BitsOfDivided(p.powLimit, 4);
            d = kAlgoSpacing;
        });
        uint32_t t = static_cast<uint32_t>(kStartTime) +
                     static_cast<uint32_t>(p.triPowForkHeight * kAlgoSpacing);
        for (int i = 0; i < 24; ++i) { // full DGW window of Ethash blocks
            chain.AppendTagged(PowAlgo::ETHASH, ethSeed, t);
            t += static_cast<uint32_t>(dt);
        }
        return chain;
    };

    FakeChain fast = build(10);
    FakeChain steady = build(kAlgoSpacing);
    const arith_uint256 seed_target = UintToArith256(p.powLimitEthash);
    const arith_uint256 fast_target = TargetOf(NextBits(fast, PowAlgo::ETHASH, p));
    const arith_uint256 steady_target = TargetOf(NextBits(steady, PowAlgo::ETHASH, p));

    BOOST_CHECK(fast_target < seed_target);          // harder than seed
    BOOST_CHECK(fast_target < steady_target);        // fast beats steady
    BOOST_CHECK(fast_target * 2 < seed_target);      // clamped ~seed/3
    BOOST_CHECK(steady_target <= seed_target);       // never above the cap
    BOOST_CHECK(steady_target * 4 > seed_target * 3); // ~unchanged (band)
}

// ---------------------------------------------------------------------------
// 4. Ethash bootstrap: the first Ethash candidate right at the fork
//    has no Ethash ancestors, so its required nBits is exactly the
//    compact of powLimitEthash -- for ANY pre-fork history.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ethash_bootstrap_from_powlimit)
{
    const auto p = MakeParams(*m_node.args);

    FakeChain h1; // uniform history, steady spacing
    AppendPreFork(h1, p, [&](int, unsigned int& nBits, int64_t& dt) {
        nBits = BitsOfDivided(p.powLimit, 4);
        dt = kAlgoSpacing;
    });
    FakeChain h2; // different nBits pattern and irregular fast spacing
    AppendPreFork(h2, p, [&](int h, unsigned int& nBits, int64_t& dt) {
        nBits = BitsOfDivided(h % 2 ? p.powLimitYespower : p.powLimit, h % 3 + 2);
        dt = 37;
    });

    const unsigned int expected = BitsOf(p.powLimitEthash);
    BOOST_CHECK_EQUAL(NextBits(h1, PowAlgo::ETHASH, p), expected);
    BOOST_CHECK_EQUAL(NextBits(h2, PowAlgo::ETHASH, p), expected);
}

// ---------------------------------------------------------------------------
// 5. Era seeding: pre-fork Yespower-era blocks carry a distinctive
//    sub-limit nBits and slow spacing, so the first post-fork Yespower
//    nBits is a retarget OF THAT HISTORY (larger target than the seed:
//    slow blocks ease difficulty), not the pure powLimit seed. Ethash,
//    with no era, bootstraps at powLimitEthash on the very same chain
//    and on a chain with completely different Yespower history.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(seeding_from_history)
{
    // Long Yespower era (38 blocks >= the 24-sample window) so the
    // first post-fork Yespower candidate already has a full window.
    const auto p = MakeParams(*m_node.args, /*yesFork=*/2, /*react=*/40, /*triFork=*/48);
    const unsigned int eraSeed = BitsOfDivided(p.powLimitYespower, 8);

    auto build = [&](unsigned int yesBits, int64_t dt) {
        FakeChain chain;
        uint32_t t = static_cast<uint32_t>(kStartTime);
        for (int h = 0; h < p.triPowForkHeight; ++h) {
            if (h > 0) t += static_cast<uint32_t>(dt);
            const unsigned int nBits =
                (h >= p.yespowerForkHeight && h < p.sha256ReactivationHeight)
                    ? yesBits : BitsOfDivided(p.powLimit, 4);
            chain.Append(/*nVersion=*/1, nBits, t);
        }
        return chain;
    };

    FakeChain seeded = build(eraSeed, /*dt=*/540); // slow Yespower era
    FakeChain other = build(BitsOfDivided(p.powLimitYespower, 2), /*dt=*/60);

    const unsigned int next_yes = NextBits(seeded, PowAlgo::YESPOWER, p);
    BOOST_CHECK_NE(next_yes, BitsOf(p.powLimitYespower)); // not the pure seed
    BOOST_CHECK(TargetOf(next_yes) > TargetOf(eraSeed));  // slow era -> eased
    BOOST_CHECK(TargetOf(next_yes) < UintToArith256(p.powLimitYespower));

    // No Ethash history anywhere: identical bootstrap on both chains.
    BOOST_CHECK_EQUAL(NextBits(seeded, PowAlgo::ETHASH, p), BitsOf(p.powLimitEthash));
    BOOST_CHECK_EQUAL(NextBits(other, PowAlgo::ETHASH, p), BitsOf(p.powLimitEthash));
}

BOOST_AUTO_TEST_SUITE_END()
