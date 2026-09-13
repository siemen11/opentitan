/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * End-to-end integration test for the DICE application on OTBN.
 *
 * Verifies:
 *   1. Creator Stage: HMAC(UDS, rom_ext) -> CDI_0, HMAC(CDI_0, bl0) -> CDI_1,
 *      and KMAC key-wrapping into Flash envelope.
 *   2. BL0 Unwrap Stage: Valid unwrapping, authentication, and share recovery.
 *   3. Tamper Detection: Invalidation and wiping upon tag mismatch.
 */

.section .text.start
test_main:
  bn.xor   w31, w31, w31

  /* --- Stage 1: Initialize Inputs for Creator Stage --- */
  la       x2, mode
  li       x3, 1
  sw       x3, 0(x2)           /* mode = 1 (Creator Stage) */

  la       x2, wfi_enable
  sw       x0, 0(x2)           /* wfi_enable = 0 */

  /* Set UDS shares */
  la       x2, uds_s0
  la       x3, test_uds_s0
  li       x4, 0
  bn.lid   x4, 0(x3)
  bn.sid   x4, 0(x2)
  la       x2, uds_s1
  la       x3, test_uds_s1
  li       x4, 1
  bn.lid   x4, 0(x3)
  bn.sid   x4, 0(x2)

  /* Set ROM_EXT KDF message shares (64 bytes each) */
  la       x2, rom_ext_kdf_s0
  la       x3, test_rom_ext_kdf_s0
  li       x4, 0
  bn.lid   x4, 0(x3)
  bn.sid   x4, 0(x2)
  bn.lid   x4, 32(x3)
  bn.sid   x4, 32(x2)

  la       x2, rom_ext_kdf_s1
  la       x3, test_rom_ext_kdf_s1
  li       x4, 1
  bn.lid   x4, 0(x3)
  bn.sid   x4, 0(x2)
  bn.lid   x4, 32(x3)
  bn.sid   x4, 32(x2)

  /* Set BL0 KDF message shares (64 bytes each) */
  la       x2, bl0_kdf_s0
  la       x3, test_bl0_kdf_s0
  li       x4, 0
  bn.lid   x4, 0(x3)
  bn.sid   x4, 0(x2)
  bn.lid   x4, 32(x3)
  bn.sid   x4, 32(x2)

  la       x2, bl0_kdf_s1
  la       x3, test_bl0_kdf_s1
  li       x4, 1
  bn.lid   x4, 0(x3)
  bn.sid   x4, 0(x2)
  bn.lid   x4, 32(x3)
  bn.sid   x4, 32(x2)

  /* Set Nonce */
  la       x2, nonce
  la       x3, test_nonce_val
  li       x4, 0
  bn.lid   x4, 0(x3)
  bn.sid   x4, 0(x2)

  /* Run Creator Stage */
  jal      x1, run_creator_stage

  /* Check Creator Stage status (expected 0) */
  la       x2, status
  lw       x8, 0(x2)

  /* Save original derived CDI_1 into w10 for comparison later */
  la       x2, cdi1_s0
  li       x3, 0
  bn.lid   x3, 0(x2)
  la       x2, cdi1_s1
  li       x3, 1
  bn.lid   x3, 0(x2)
  bn.xor   w10, w0, w1         /* w10 <= original CDI1 */

  /* Wipe CDI_1 shares from DMEM */
  li       x3, 31
  la       x2, cdi1_s0
  bn.sid   x3, 0(x2)
  la       x2, cdi1_s1
  bn.sid   x3, 0(x2)

  /* --- Stage 2: Run BL0 Unwrap Stage --- */
  la       x2, mode
  li       x3, 2
  sw       x3, 0(x2)           /* mode = 2 (BL0 Unwrap) */

  jal      x1, run_bl0_unwrap

  /* Check Unwrap status (expected 0) */
  la       x2, status
  lw       x9, 0(x2)

  /* Load recovered CDI_1 into w1 */
  la       x2, cdi1_s0
  li       x3, 0
  bn.lid   x3, 0(x2)
  la       x2, cdi1_s1
  li       x3, 1
  bn.lid   x3, 0(x2)
  bn.xor   w1, w0, w1          /* w1 <= recovered CDI1 */

  /* Check if recovered CDI1 matches original CDI1: diff in w3 */
  bn.xor   w3, w1, w10         /* w3 <= must be 0 */

  /* --- Stage 3: Test Tamper Detection --- */
  /* Corrupt ciphertext in wrapped_key */
  la       x2, wrapped_key
  li       x3, 4
  bn.lid   x3, 32(x2)
  bn.not   w5, w31
  bn.rshi  w5, w31, w5 >> 255
  bn.xor   w4, w4, w5
  bn.sid   x3, 32(x2)

  /* Run BL0 Unwrap again on tampered envelope */
  jal      x1, run_bl0_unwrap

  /* Save tampered unwrap status to x10 (expected 1 = failure) */
  la       x2, status
  lw       x10, 0(x2)

  /* Check destination buffers are wiped: w4 <= cdi1_s0 ^ cdi1_s1 */
  la       x2, cdi1_s0
  li       x3, 4
  bn.lid   x3, 0(x2)
  la       x2, cdi1_s1
  li       x3, 5
  bn.lid   x3, 0(x2)
  bn.xor   w4, w4, w5          /* w4 <= must be 0 */

  ecall

.data

.balign 32
test_uds_s0:
  .word 0x01020304 ^ 0xa5a5a5a5
  .word 0x05060708 ^ 0xa5a5a5a5
  .word 0x090a0b0c ^ 0xa5a5a5a5
  .word 0x0d0e0f10 ^ 0xa5a5a5a5
  .word 0x11121314 ^ 0xa5a5a5a5
  .word 0x15161718 ^ 0xa5a5a5a5
  .word 0x191a1b1c ^ 0xa5a5a5a5
  .word 0x1d1e1f20 ^ 0xa5a5a5a5

.balign 32
test_uds_s1:
  .word 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5
  .word 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5

.balign 32
test_rom_ext_kdf_s0:
  .word 0x01000000 ^ 0x5a5a5a5a
  .word 0x5f494443 ^ 0x5a5a5a5a
  .word 0x65747441 ^ 0x5a5a5a5a
  .word 0x24007473 ^ 0x5a5a5a5a
  .word 0x28212223 ^ 0x5a5a5a5a
  .word 0x2c252627 ^ 0x5a5a5a5a
  .word 0x30292a2b ^ 0x5a5a5a5a
  .word 0x342d2e2f ^ 0x5a5a5a5a
  .word 0x38313233 ^ 0x5a5a5a5a
  .word 0x3c353637 ^ 0x5a5a5a5a
  .word 0x40393a3b ^ 0x5a5a5a5a
  .word 0x003d3e3f ^ 0x5a5a5a5a
  .word 0x80000100 ^ 0x5a5a5a5a
  .word 0x00000000 ^ 0x5a5a5a5a
  .word 0x00000000 ^ 0x5a5a5a5a
  .word 0x98030000 ^ 0x5a5a5a5a

.balign 32
test_rom_ext_kdf_s1:
  .word 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a
  .word 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a
  .word 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a
  .word 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a

.balign 32
test_bl0_kdf_s0:
  .word 0x01000000 ^ 0x3c3c3c3c
  .word 0x5f494443 ^ 0x3c3c3c3c
  .word 0x65747441 ^ 0x3c3c3c3c
  .word 0x44007473 ^ 0x3c3c3c3c
  .word 0x48414243 ^ 0x3c3c3c3c
  .word 0x4c454647 ^ 0x3c3c3c3c
  .word 0x50494a4b ^ 0x3c3c3c3c
  .word 0x544d4e4f ^ 0x3c3c3c3c
  .word 0x58515253 ^ 0x3c3c3c3c
  .word 0x5c555657 ^ 0x3c3c3c3c
  .word 0x60595a5b ^ 0x3c3c3c3c
  .word 0x005d5e5f ^ 0x3c3c3c3c
  .word 0x80000100 ^ 0x3c3c3c3c
  .word 0x00000000 ^ 0x3c3c3c3c
  .word 0x00000000 ^ 0x3c3c3c3c
  .word 0x98030000 ^ 0x3c3c3c3c

.balign 32
test_bl0_kdf_s1:
  .word 0x3c3c3c3c, 0x3c3c3c3c, 0x3c3c3c3c, 0x3c3c3c3c
  .word 0x3c3c3c3c, 0x3c3c3c3c, 0x3c3c3c3c, 0x3c3c3c3c
  .word 0x3c3c3c3c, 0x3c3c3c3c, 0x3c3c3c3c, 0x3c3c3c3c
  .word 0x3c3c3c3c, 0x3c3c3c3c, 0x3c3c3c3c, 0x3c3c3c3c

.balign 32
test_nonce_val:
  .word 0x11111111, 0x22222222, 0x33333333, 0x44444444
  .word 0x55555555, 0x66666666, 0x77777777, 0x88888888
