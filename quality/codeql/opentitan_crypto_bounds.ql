// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

/**
 * @name OpenTitan Crypto Buffer Overflow
 * @description Identifies buffer overflows when using the OTCRYPTO_MAKE_BUF macro by comparing the statically allocated array size with the length argument passed to the macro.
 * @kind problem
 * @problem.severity error
 * @id cpp/opentitan-crypto-buffer-overflow
 */

import cpp

from MacroInvocation mi, VariableAccess va, ArrayType arr, int declared_len, int array_len
where
  // Scope analysis to the cryptolib modules to avoid false positives.
  (mi.getFile().getAbsolutePath().matches("%/sw/device/lib/crypto/%") or
   mi.getFile().getAbsolutePath().matches("%/sw/device/tests/crypto/%")) and

  mi.getMacroName() = "OTCRYPTO_MAKE_BUF" and

  // Extract the target variable being passed to the macro and identify its underlying array capacity.
  va.getTarget().getName() = mi.getUnexpandedArgument(1).regexpReplaceAll("\\(.*\\)", "").trim() and
  va.getTarget().getType() = arr and
  array_len = arr.getArraySize() and

  // Compare the statically determined capacity against the declared length.
  declared_len = mi.getUnexpandedArgument(2).toInt() and
  declared_len > array_len
select mi, "Buffer overflow detected: '" + va.getTarget().getName() + "' has a static capacity of " + array_len + " words, but the macro declares a length of " + declared_len + " words."
