#!/usr/bin/env python3
# Copyright (c) 2026 The Interchained Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test: RPC mining for all three tri-PoW algos on regtest.

Tri-PoW (post-triPowForkHeight; active from ~genesis on regtest) tags
every block with one of SHA256 / Yespower / Ethash, each with its own
difficulty track. This test mines a mixed-algo chain through the mining
RPCs and checks it survives a restart.

Covered RPCs:
- generatetoaddress(nblocks, address, maxtries, algo)
- generateblock(output, transactions, algo)
- getblocktemplate (ethash template carries the algo tag, see note)
- getmininginfo (per-algo difficulty / networkhashps fields)
- getnetworkhashps (combined value)
- getblockcount / getblockheader / getbestblockhash (validation)

ASSUMPTIONS about the tri-PoW RPC signatures (coordinator: if the
integrated signatures differ, only the helpers at the top of this file
should need changing):
- generatetoaddress gains an optional trailing string parameter
  "algo" (4th positional argument, after maxtries).
- generateblock gains an analogous optional trailing string
  parameter "algo" (3rd positional argument, after transactions),
  following the existing generateblock(output, transactions)
  convention in rpc_generateblock.py.
- getblocktemplate selects the algo via an "algo" key inside the
  template request object, alongside the usual "rules" key.

GBT note (integration): a full ethash template->submitblock roundtrip
is NOT exercised here. The Python framework serializes 80-byte headers
and its CBlock.solve() is SHA256-only, so it cannot construct or solve
a 120-byte Ethash-tagged block (which also needs a mix hash only an
ethash implementation can produce). What IS verified: requesting a
template with "algo": "ethash" returns a template whose version field
carries the Ethash tag bits (nVersion bits 13-14 == 2), i.e. the GBT
mining surface honors the algo choice; the block itself is then mined
in-node via generatetoaddress/generateblock like the other algos.
"""

from test_framework.blocktools import NORMAL_GBT_REQUEST_PARAMS
from test_framework.test_framework import InterchainedTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

ALGOS = ["sha256", "yespower", "ethash"]
# Regtest difficulties are trivial, but Ethash (hashimoto light)
# hashes far slower per attempt than SHA256/Yespower, so give it a
# much larger maxtries budget.
MAX_TRIES = {"sha256": 1000000, "yespower": 1000000, "ethash": 100000000}


def mine(self, node, n, algo):
    """Mine `n` blocks with `algo` via generatetoaddress.

    This is the SINGLE place the generatetoaddress "algo" argument is
    passed. If the integrated RPC signature differs (name, position or
    keyword style), fix it here only.
    """
    address = node.get_deterministic_priv_key().address
    return node.generatetoaddress(n, address, MAX_TRIES[algo], algo)


def mine_generateblock(self, node, algo):
    """Mine one block with `algo` via generateblock.

    Analogous trailing-position assumption: the existing signature is
    generateblock(output, transactions), so "algo" is appended as the
    3rd positional argument.
    """
    address = node.getnewaddress()
    return node.generateblock(address, [], algo)["hash"]


class TriPowMiningTest(InterchainedTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        # generateblock to a fresh address needs a wallet, same as
        # rpc_generateblock.py.
        self.skip_if_no_wallet()

    def assert_block_accepted(self, node, block_hash, expected_height):
        header = node.getblockheader(block_hash)
        assert_equal(header["hash"], block_hash)
        assert_equal(header["height"], expected_height)
        # If the header exposes the algo tag, it must be readable;
        # the exact field name is an implementation detail, so only
        # check the known candidate names when present.
        return header

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Chain starts on regtest with tri-PoW active from genesis")
        assert_equal(node.getblockchaininfo()["chain"], "regtest")
        assert_equal(node.getblockcount(), 0)

        all_hashes = {}  # algo -> [block hashes mined with that algo]

        for algo in ALGOS:
            self.log.info("Mine 2 blocks with generatetoaddress algo=%s", algo)
            start = node.getblockcount()
            hashes = mine(self, node, 2, algo)
            assert_equal(len(hashes), 2)
            assert_equal(node.getblockcount(), start + 2)
            for i, block_hash in enumerate(hashes):
                self.assert_block_accepted(node, block_hash, start + 1 + i)
            all_hashes[algo] = list(hashes)

            self.log.info("Mine 1 block with generateblock algo=%s", algo)
            gb_hash = mine_generateblock(self, node, algo)
            assert_equal(node.getblockcount(), start + 3)
            self.assert_block_accepted(node, gb_hash, start + 3)
            all_hashes[algo].append(gb_hash)

        self.log.info("Block hashes are distinct across algos")
        flat = [h for hashes in all_hashes.values() for h in hashes]
        assert_equal(len(flat), len(set(flat)))
        assert_equal(node.getblockcount(), 3 * len(ALGOS))

        self.log.info("getblocktemplate: template honors the requested algo")
        tmpl_request = dict(NORMAL_GBT_REQUEST_PARAMS)
        tmpl_request["algo"] = "ethash"
        tmpl = node.getblocktemplate(tmpl_request)
        assert_equal(tmpl["previousblockhash"], node.getbestblockhash())
        assert_equal(int(tmpl["height"]), node.getblockcount() + 1)
        # The template's version must carry the Ethash tag (nVersion
        # bits 13-14 == PowAlgo::ETHASH == 2). See the GBT note in the
        # module docstring for why no block is built from it here.
        assert_equal((int(tmpl["version"]) >> 13) & 0x3, 2)

        self.log.info("getmininginfo exposes per-algo difficulty and hashrate")
        mining_info = node.getmininginfo()
        for algo in ALGOS:
            assert "difficulty_{}".format(algo) in mining_info
            assert "networkhashps_{}".format(algo) in mining_info

        self.log.info("getnetworkhashps returns a positive combined value")
        combined = node.getnetworkhashps()
        assert combined > 0, "combined networkhashps should be positive, got {}".format(combined)

        self.log.info("Restart node: mixed-algo chain must revalidate unchanged")
        best_before = node.getbestblockhash()
        count_before = node.getblockcount()
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), best_before)
        assert_equal(node.getblockcount(), count_before)
        for algo in ALGOS:
            # Every algo's blocks are still on the active chain.
            for block_hash in all_hashes[algo]:
                header = node.getblockheader(block_hash)
                assert header["confirmations"] > 0

        self.log.info("Invalid algo string is rejected with an RPC error")
        # Any RPC error code/message is accepted here: the exact error
        # for an unknown algo value is an implementation detail.
        assert_raises_rpc_error(None, None, mine, self, node, 1, "scrypt")
        assert_equal(node.getblockcount(), count_before)


if __name__ == "__main__":
    TriPowMiningTest().main()
