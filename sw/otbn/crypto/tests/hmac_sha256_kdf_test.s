/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Standalone test for masked NIST SP 800-108 Counter Mode KDF on OTBN.
 *
 * Test vector:
 *   Key: 32 bytes of 0x0b
 *   Context: 32 bytes of 0x00..0x1f
 *   Label: "CDI_Attest"
 *   KDF: cc8b8fdc543685d3a22cdfa4908ae246230d59e5ac34a831c78764633be2a6db
 */

.section .text.start
main:
  /* Load pointers to key, KDF message block, and output shares */
  la      x10, key_s0
  la      x11, key_s1
  la      x12, kdf_s0
  la      x13, kdf_s1
  la      x14, out_s0
  la      x15, out_s1

  /* Run masked NIST SP 800-108 KDF */
  jal     x1, hmac_sha256_kdf_masked

  /* Load final KDF output shares into registers to unmask and verify */
  la      x2, out_s0
  li      x3, 0
  bn.lid  x3, 0(x2)
  la      x2, out_s1
  li      x3, 1
  bn.lid  x3, 0(x2)

  /* The unmasked result must match expected CDI */
  bn.xor  w2, w0, w1

  ecall

.data

/* Key: 32 bytes of 0x0b, masked with 0x12345678 */
.balign 32
key_s0:
  .word 0x0b0b0b0b ^ 0x12345678
  .word 0x0b0b0b0b ^ 0x12345678
  .word 0x0b0b0b0b ^ 0x12345678
  .word 0x0b0b0b0b ^ 0x12345678
  .word 0x0b0b0b0b ^ 0x12345678
  .word 0x0b0b0b0b ^ 0x12345678
  .word 0x0b0b0b0b ^ 0x12345678
  .word 0x0b0b0b0b ^ 0x12345678

.balign 32
key_s1:
  .word 0x12345678, 0x12345678, 0x12345678, 0x12345678
  .word 0x12345678, 0x12345678, 0x12345678, 0x12345678

/* SP 800-108 formatted block 1 (64 bytes), masked with 0xdeadbeef */
.balign 32
kdf_s0:
  .word 0x01000000 ^ 0xdeadbeef
  .word 0x5f494443 ^ 0xdeadbeef
  .word 0x65747441 ^ 0xdeadbeef
  .word 0x00007473 ^ 0xdeadbeef
  .word 0x04030201 ^ 0xdeadbeef
  .word 0x08070605 ^ 0xdeadbeef
  .word 0x0c0b0a09 ^ 0xdeadbeef
  .word 0x100f0e0d ^ 0xdeadbeef
  .word 0x14131211 ^ 0xdeadbeef
  .word 0x18171615 ^ 0xdeadbeef
  .word 0x1c1b1a19 ^ 0xdeadbeef
  .word 0x001f1e1d ^ 0xdeadbeef
  .word 0x80000100 ^ 0xdeadbeef
  .word 0x00000000 ^ 0xdeadbeef
  .word 0x00000000 ^ 0xdeadbeef
  .word 0x98030000 ^ 0xdeadbeef

.balign 32
kdf_s1:
  .word 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef
  .word 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef
  .word 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef
  .word 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef

.bss
.balign 32
out_s0:
  .zero 32
.balign 32
out_s1:
  .zero 32
