/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Standalone test for DICE KMAC key wrapping and unwrapping.
 *
 * Tests:
 *   1. Wrapping CDI1 into wrapped key structure (Nonce || Ciphertext || Tag).
 *   2. Unwrapping valid structure, verifying tag, and restoring CDI1 shares.
 *   3. Tampering with ciphertext, verifying authentication tag mismatch failure.
 */

.section .text.start
main:
  bn.xor   w31, w31, w31

  /* --- Step 1: Wrap CDI1 --- */
  la       x10, test_cdi1_s0
  la       x11, test_cdi1_s1
  la       x12, test_nonce
  la       x13, wrapped_key
  jal      x1, kmac_wrap_cdi1

  /* Wipe original CDI1 shares */
  la       x2, test_cdi1_s0
  li       x3, 31
  bn.sid   x3, 0(x2)
  la       x2, test_cdi1_s1
  bn.sid   x3, 0(x2)

  /* --- Step 2: Unwrap valid structure --- */
  la       x10, wrapped_key
  la       x11, test_cdi1_s0
  la       x12, test_cdi1_s1
  jal      x1, kmac_unwrap_cdi1

  /* Save unwrap status to x8 (expected 0) */
  addi     x8, x10, 0

  /* Load recovered CDI1 shares and unmask into w1 */
  la       x2, test_cdi1_s0
  li       x3, 0
  bn.lid   x3, 0(x2)
  la       x2, test_cdi1_s1
  li       x3, 1
  bn.lid   x3, 0(x2)
  bn.xor   w1, w0, w1          /* w1 <= recovered CDI1 (expected 0x4242...42) */

  /* --- Step 3: Test tampering / authentication failure --- */
  /* Flip a bit in the ciphertext (offset 32 of wrapped_key) */
  la       x2, wrapped_key
  li       x3, 4
  bn.lid   x3, 32(x2)
  /* Flip bit 0 of w4 */
  bn.not   w5, w31
  bn.rshi  w5, w31, w5 >> 255  /* w5 = 1 */
  bn.xor   w4, w4, w5
  bn.sid   x3, 32(x2)

  /* Attempt to unwrap tampered envelope */
  la       x10, wrapped_key
  la       x11, test_cdi1_s0
  la       x12, test_cdi1_s1
  jal      x1, kmac_unwrap_cdi1

  /* Save tamper unwrap status to x9 (expected 1 = failure) */
  addi     x9, x10, 0

  /* Check that destination shares are wiped (load into w2 and w3 to keep w1 intact) */
  la       x2, test_cdi1_s0
  li       x3, 2
  bn.lid   x3, 0(x2)
  la       x2, test_cdi1_s1
  li       x3, 3
  bn.lid   x3, 0(x2)
  bn.xor   w2, w2, w3          /* w2 <= must be 0 */

  ecall

.data

/* Test CDI1: 32 bytes of 0x42, split into 2 shares */
.balign 32
test_cdi1_s0:
  .word 0x42424242 ^ 0x11223344
  .word 0x42424242 ^ 0x11223344
  .word 0x42424242 ^ 0x11223344
  .word 0x42424242 ^ 0x11223344
  .word 0x42424242 ^ 0x11223344
  .word 0x42424242 ^ 0x11223344
  .word 0x42424242 ^ 0x11223344
  .word 0x42424242 ^ 0x11223344

.balign 32
test_cdi1_s1:
  .word 0x11223344
  .word 0x11223344
  .word 0x11223344
  .word 0x11223344
  .word 0x11223344
  .word 0x11223344
  .word 0x11223344
  .word 0x11223344

/* Test Nonce: 32 bytes */
.balign 32
test_nonce:
  .word 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c
  .word 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c

.bss
.balign 32
wrapped_key:
  .zero 96
