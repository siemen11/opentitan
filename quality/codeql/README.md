<!--
Copyright lowRISC contributors (OpenTitan project).
Licensed under the Apache License, Version 2.0, see LICENSE for details.
SPDX-License-Identifier: Apache-2.0
-->

# OpenTitan CodeQL Static Analysis

This directory contains custom CodeQL queries (`.ql` files) for the OpenTitan project.

## Overview
OpenTitan uses GitHub's CodeQL engine to run static analysis on C/C++ code. Currently, only `cryptolib` (`//sw/device/lib/crypto:otcrypto`) and its tests (`//sw/device/tests/crypto/...`) are built and scanned; the rest of the codebase is not yet covered.

The GitHub Actions workflow (`.github/workflows/codeql-crypto.yml`) traces the `cryptolib` build and runs CodeQL's `security-and-quality` suite, which checks for standard C/C++ bugs such as:
- Out-of-bounds array reads and writes
- Use-after-free and double-frees
- Uninitialized variable usage
- Integer overflows

## Custom Queries
Because CodeQL natively struggles to associate standard pointer bounds with lengths when they are wrapped in custom structs (e.g., `otcrypto_word32_buf_t`), we include custom AST queries here for OpenTitan-specific APIs.

Currently, `opentitan_crypto_bounds.ql` checks uses of the `OTCRYPTO_MAKE_BUF` macro in `sw/device/lib/crypto/` and `sw/device/tests/crypto/`, verifying that the declared buffer length does not exceed the statically allocated array capacity.
