/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Standalone test for masked HMAC-SHA256 on OTBN.
 *
 * Test vector:
 *   Key: 32 bytes of 0x0b
 *   Message: "OpenTitan DICE Attestation Test!" (32 bytes = 256 bits)
 *   HMAC-SHA256: a9afbc4cb44991f647c5d5ed62d8210327ed173509aca1fe38d5896907461102
 */

.section .text.start
main:
  /* Load pointers to key, message, and output shares */
  la      x10, key_s0
  la      x11, key_s1
  la      x12, msg_s0
  la      x13, msg_s1
  la      x14, out_s0
  la      x15, out_s1

  /* Run masked HMAC-SHA256 */
  jal     x1, hmac_sha256_masked

  /* Load final HMAC output shares into registers to unmask and verify */
  la      x2, out_s0
  li      x3, 0
  bn.lid  x3, 0(x2)
  la      x2, out_s1
  li      x3, 1
  bn.lid  x3, 0(x2)

  /* The unmasked result must match expected HMAC */
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
  .word 0x12345678
  .word 0x12345678
  .word 0x12345678
  .word 0x12345678
  .word 0x12345678
  .word 0x12345678
  .word 0x12345678
  .word 0x12345678

/* Message: "OpenTitan DICE Attestation Test!", masked with 0xdeadbeef */
.balign 32
msg_s0:
  .word 0x6e65704f ^ 0xdeadbeef
  .word 0x61746954 ^ 0xdeadbeef
  .word 0x4944206e ^ 0xdeadbeef
  .word 0x41204543 ^ 0xdeadbeef
  .word 0x73657474 ^ 0xdeadbeef
  .word 0x69746174 ^ 0xdeadbeef
  .word 0x54206e6f ^ 0xdeadbeef
  .word 0x21747365 ^ 0xdeadbeef

.balign 32
msg_s1:
  .word 0xdeadbeef
  .word 0xdeadbeef
  .word 0xdeadbeef
  .word 0xdeadbeef
  .word 0xdeadbeef
  .word 0xdeadbeef
  .word 0xdeadbeef
  .word 0xdeadbeef

.bss
.balign 32
out_s0:
  .zero 32
.balign 32
out_s1:
  .zero 32
