# Vendored ethash library

Upstream: https://github.com/chfast/ethash
Version:  1.1.0 (ETHASH_VERSION in include/ethash/version.h, revision "23")
Commit:   17e80309ceb592b9b5175b831549a1cc160d1a08 (v1.1.0-2-g17e8030)
License:  Apache License, Version 2.0 — see LICENSE in this directory.
Vendored: 2026-11-07, for Interchained tri-PoW (Ethash PoW lane).

Only the files needed for light verification / hashimoto-light are kept,
mirroring the upstream layout so upstream relative includes work unchanged:

- include/ethash/{ethash,hash_types,keccak,version}.h and the .hpp wrappers
- lib/ethash/ethash.cpp (hashimoto light/full, epoch contexts)
- lib/ethash/ethash-internal.hpp, lib/ethash/endianness.hpp
- lib/ethash/primes.{c,h} (light-cache / dataset size primes)
- lib/keccak/keccak.c (Keccak-256/512)
- lib/support/attributes.h

Not vendored: global_context, tests, benchmarks, CMake files.
No upstream file was modified.
