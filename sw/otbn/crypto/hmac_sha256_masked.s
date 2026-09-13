/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

.globl hmac_sha256_masked
.globl hmac_sha256_kdf_masked

.text

/**
 * Masked NIST SP 800-108 KDF in Counter Mode using HMAC-SHA256.
 *
 * Implements SP 800-108 Counter Mode:
 *   CDI = HMAC-SHA256(Key, [1]_2 || Label || 0x00 || Context || [L]_2)
 *
 * All key material, intermediate digests, and outputs are maintained in 2 boolean shares.
 *
 * @param[in]  x10: Pointer to Share 0 of 256-bit key in DMEM
 * @param[in]  x11: Pointer to Share 1 of 256-bit key in DMEM
 * @param[in]  x12: Pointer to Share 0 of 64-byte KDF Block 1 in DMEM
 * @param[in]  x13: Pointer to Share 1 of 64-byte KDF Block 1 in DMEM
 * @param[out] x14: Pointer to Share 0 of 256-bit output digest in DMEM
 * @param[out] x15: Pointer to Share 1 of 256-bit output digest in DMEM
 */
hmac_sha256_kdf_masked:
  /* Save return address and output pointers in callee-preserved GPRs */
  addi     x28, x1, 0
  addi     x29, x14, 0
  addi     x27, x15, 0

  /* Zero register */
  bn.xor   w31, w31, w31

  /* Load key shares: w0 <= K_s0, w1 <= K_s1 */
  li       x2, 0
  bn.lid   x2, 0(x10)
  li       x2, 1
  bn.lid   x2, 0(x11)

  /* Load ipad constant: w4 <= 0x363636...36 */
  la       x2, hmac_ipad_const
  li       x3, 4
  bn.lid   x3, 0(x2)

  /* Construct Block 0 of Inner Hash: K_i = K_pad ^ ipad (64 bytes) */
  bn.xor   w7, w0, w4
  la       x2, hmac_mbuf_s0
  li       x3, 7
  bn.sid   x3, 0(x2)           /* Block 0 lower: K_s0 ^ ipad */
  li       x3, 4
  bn.sid   x3, 32(x2)          /* Block 0 upper: ipad */

  la       x2, hmac_mbuf_s1
  li       x3, 1
  bn.sid   x3, 0(x2)           /* Block 0 lower: K_s1 */
  li       x3, 31
  bn.sid   x3, 32(x2)          /* Block 0 upper: 0 */

  /* Construct Block 1 for KDF from 64-byte preformatted message block in x12 and x13 */
  li       x3, 2
  bn.lid   x3, 0(x12)          /* Block 1 s0 lower (32 bytes) */
  li       x3, 6
  bn.lid   x3, 32(x12)         /* Block 1 s0 upper (32 bytes) */
  li       x3, 3
  bn.lid   x3, 0(x13)          /* Block 1 s1 lower (32 bytes) */
  li       x3, 7
  bn.lid   x3, 32(x13)         /* Block 1 s1 upper (32 bytes) */

  la       x2, hmac_mbuf_s0
  li       x3, 2
  bn.sid   x3, 64(x2)          /* Block 1 lower: s0 */
  li       x3, 6
  bn.sid   x3, 96(x2)          /* Block 1 upper: s0 */

  la       x2, hmac_mbuf_s1
  li       x3, 3
  bn.sid   x3, 64(x2)          /* Block 1 lower: s1 */
  li       x3, 7
  bn.sid   x3, 96(x2)          /* Block 1 upper: s1 */

  jal      x0, _hmac_inner_outer_common

/**
 * Masked HMAC-SHA256 for 256-bit keys and 256-bit messages.
 *
 * Implements FIPS 198-1 with first-order boolean masking:
 *   HMAC(K, M) = SHA256((K ^ opad) || SHA256((K ^ ipad) || M))
 *
 * All key material, intermediate digests, and outputs are maintained in 2 boolean shares.
 *
 * @param[in]  x10: Pointer to Share 0 of 256-bit key in DMEM
 * @param[in]  x11: Pointer to Share 1 of 256-bit key in DMEM
 * @param[in]  x12: Pointer to Share 0 of 256-bit message in DMEM
 * @param[in]  x13: Pointer to Share 1 of 256-bit message in DMEM
 * @param[out] x14: Pointer to Share 0 of 256-bit output digest in DMEM
 * @param[out] x15: Pointer to Share 1 of 256-bit output digest in DMEM
 *
 * Clobbered registers: x2, x3, x5, x6, x7, x8, x9, x10-x15, x20-x23, x30,
 *                      w0-w31
 */
hmac_sha256_masked:
  /* Save return address and output pointers in callee-preserved GPRs */
  addi     x28, x1, 0
  addi     x29, x14, 0
  addi     x27, x15, 0

  /* Zero register */
  bn.xor   w31, w31, w31

  /* Load key shares: w0 <= K_s0, w1 <= K_s1 */
  li       x2, 0
  bn.lid   x2, 0(x10)
  li       x2, 1
  bn.lid   x2, 0(x11)

  /* Load message shares: w2 <= M_s0, w3 <= M_s1 */
  li       x2, 2
  bn.lid   x2, 0(x12)
  li       x2, 3
  bn.lid   x2, 0(x13)

  /* Load ipad constant: w4 <= 0x363636...36 */
  la       x2, hmac_ipad_const
  li       x3, 4
  bn.lid   x3, 0(x2)

  /* Load SHA-256 padding for 768-bit total length (96 bytes): w6 */
  la       x2, hmac_pad_768
  li       x3, 6
  bn.lid   x3, 0(x2)

  /* --- Construct Inner Hash Message Buffer (hmac_mbuf_s0, hmac_mbuf_s1) ---
   *
   * Block 0: K_i = K_pad ^ ipad (64 bytes)
   *   Share 0 lower 256: K_s0 ^ ipad (w0 ^ w4)
   *   Share 0 upper 256: 0 ^ ipad    (w4)
   *   Share 1 lower 256: K_s1        (w1)
   *   Share 1 upper 256: 0           (w31)
   *
   * Block 1: M || Padding (64 bytes)
   *   Share 0 lower 256: M_s0        (w2)
   *   Share 0 upper 256: Padding     (w6)
   *   Share 1 lower 256: M_s1        (w3)
   *   Share 1 upper 256: 0           (w31)
   */
  bn.xor   w7, w0, w4
  la       x2, hmac_mbuf_s0
  li       x3, 7
  bn.sid   x3, 0(x2)           /* Block 0 lower: K_s0 ^ ipad */
  li       x3, 4
  bn.sid   x3, 32(x2)          /* Block 0 upper: ipad */
  li       x3, 2
  bn.sid   x3, 64(x2)          /* Block 1 lower: M_s0 */
  li       x3, 6
  bn.sid   x3, 96(x2)          /* Block 1 upper: padding */

  la       x2, hmac_mbuf_s1
  li       x3, 1
  bn.sid   x3, 0(x2)           /* Block 0 lower: K_s1 */
  li       x3, 31
  bn.sid   x3, 32(x2)          /* Block 0 upper: 0 */
  li       x3, 3
  bn.sid   x3, 64(x2)          /* Block 1 lower: M_s1 */
  li       x3, 31
  bn.sid   x3, 96(x2)          /* Block 1 upper: 0 */

_hmac_inner_outer_common:
  /* Set initial hash state to standard SHA-256 IV */
  jal      x1, hmac_init_sha256_state

  /* Run inner SHA-256 on 2 blocks */
  la       x10, hmac_mbuf_s0
  la       x11, hmac_mbuf_s1
  li       x30, 2
  jal      x1, sha256_masked

  /* Load inner hash result from state_s0, state_s1: w0 <= state_s0, w1 <= state_s1 */
  la       x2, state_s0
  li       x3, 0
  bn.lid   x3, 0(x2)
  la       x2, state_s1
  li       x3, 1
  bn.lid   x3, 0(x2)

  /* Reverse 32 bytes of inner hash shares to format for outer hash message */
  jal      x1, hmac_rev32_w0_w1

  /* --- Construct Outer Hash Message Buffer ---
   *
   * Block 0: K_o = K_pad ^ opad (64 bytes)
   *   Share 0 lower 256: K_s0 ^ opad
   *   Share 0 upper 256: opad
   *   Share 1 lower 256: K_s1
   *   Share 1 upper 256: 0
   *
   * Block 1: inner_digest || Padding (64 bytes)
   *   Share 0 lower 256: inner_s0 (w0)
   *   Share 0 upper 256: Padding  (w6)
   *   Share 1 lower 256: inner_s1 (w1)
   *   Share 1 upper 256: 0
   */
  /* Reload K_s0 and K_s1 into w2 and w3 */
  la       x2, hmac_mbuf_s1
  li       x3, 3
  bn.lid   x3, 0(x2)           /* w3 <= K_s1 */
  la       x2, hmac_mbuf_s0
  li       x3, 2
  bn.lid   x3, 0(x2)           /* w2 <= K_s0 ^ ipad */
  la       x2, hmac_ipad_const
  li       x3, 4
  bn.lid   x3, 0(x2)
  bn.xor   w2, w2, w4          /* w2 <= K_s0 */
  la       x2, hmac_opad_const
  li       x3, 5
  bn.lid   x3, 0(x2)
  bn.xor   w7, w2, w5          /* w7 <= K_s0 ^ opad */

  /* Reload padding */
  la       x2, hmac_pad_768
  li       x3, 6
  bn.lid   x3, 0(x2)

  /* Store outer message buffer */
  la       x2, hmac_mbuf_s0
  li       x3, 7
  bn.sid   x3, 0(x2)           /* Block 0 lower: K_s0 ^ opad */
  li       x3, 5
  bn.sid   x3, 32(x2)          /* Block 0 upper: opad */
  li       x3, 0
  bn.sid   x3, 64(x2)          /* Block 1 lower: inner_s0 */
  li       x3, 6
  bn.sid   x3, 96(x2)          /* Block 1 upper: padding */

  la       x2, hmac_mbuf_s1
  li       x3, 3
  bn.sid   x3, 0(x2)           /* Block 0 lower: K_s1 */
  li       x3, 31
  bn.sid   x3, 32(x2)          /* Block 0 upper: 0 */
  li       x3, 1
  bn.sid   x3, 64(x2)          /* Block 1 lower: inner_s1 */
  li       x3, 31
  bn.sid   x3, 96(x2)          /* Block 1 upper: 0 */

  /* Reset initial hash state to standard SHA-256 IV */
  jal      x1, hmac_init_sha256_state

  /* Run outer SHA-256 on 2 blocks */
  la       x10, hmac_mbuf_s0
  la       x11, hmac_mbuf_s1
  li       x30, 2
  jal      x1, sha256_masked

  /* Load final HMAC state from state_s0, state_s1 */
  la       x2, state_s0
  li       x3, 0
  bn.lid   x3, 0(x2)
  la       x2, state_s1
  li       x3, 1
  bn.lid   x3, 0(x2)

  /* Reverse 32 bytes of final HMAC shares to output standard digest byte order */
  jal      x1, hmac_rev32_w0_w1

  /* Write final HMAC digest shares to caller's destination pointers */
  li       x3, 0
  bn.sid   x3, 0(x29)
  li       x3, 1
  bn.sid   x3, 0(x27)

  /* Restore return address and return */
  addi     x1, x28, 0
  ret

/**
 * Reverse all 32 bytes of 256-bit registers w0 and w1 independently.
 *
 * Each share undergoes:
 *   1. Parallel 32-bit word byte swap (bswap32)
 *   2. 8-word sequence reversal
 *
 * Preserves first-order boolean masking: w0 and w1 are never mixed.
 */
hmac_rev32_w0_w1:
  /* Load bswap32 mask into w8 */
  la       x2, hmac_bswap32_mask
  li       x3, 8
  bn.lid   x3, 0(x2)

  /* Step 1: byte-swap each 32-bit word in w0 (Share 0) */
  bn.and   w24, w8,  w0
  bn.and   w25, w8,  w0 >> 8
  bn.and   w26, w8,  w0 >> 16
  bn.and   w27, w8,  w0 >> 24
  bn.or    w0,  w25, w24 << 8
  bn.or    w0,  w26, w0 << 8
  bn.or    w0,  w27, w0 << 8

  /* Step 2: reverse the 8 words of w0 */
  bn.xor   w2,  w2,  w2
  loopi    8, 3
    bn.rshi  w28, w31, w0 >> 224
    bn.rshi  w0,  w0,  w31 >> 224
    bn.rshi  w2,  w28, w2 >> 32
  bn.mov   w0,  w2

  /* Step 3: byte-swap each 32-bit word in w1 (Share 1) */
  bn.and   w24, w8,  w1
  bn.and   w25, w8,  w1 >> 8
  bn.and   w26, w8,  w1 >> 16
  bn.and   w27, w8,  w1 >> 24
  bn.or    w1,  w25, w24 << 8
  bn.or    w1,  w26, w1 << 8
  bn.or    w1,  w27, w1 << 8

  /* Step 4: reverse the 8 words of w1 */
  bn.xor   w2,  w2,  w2
  loopi    8, 3
    bn.rshi  w28, w31, w1 >> 224
    bn.rshi  w1,  w1,  w31 >> 224
    bn.rshi  w2,  w28, w2 >> 32
  bn.mov   w1,  w2

  ret

/**
 * Helper to initialize state_s0 and state_s1 with standard SHA-256 IV.
 */
hmac_init_sha256_state:
  la       x2, hmac_iv_s0
  li       x3, 30
  bn.lid   x3, 0(x2)
  la       x2, state_s0
  bn.sid   x3, 0(x2)

  la       x2, hmac_iv_s1
  li       x3, 29
  bn.lid   x3, 0(x2)
  la       x2, state_s1
  bn.sid   x3, 0(x2)
  ret

.data
.balign 32
hmac_ipad_const:
  .word 0x36363636, 0x36363636, 0x36363636, 0x36363636
  .word 0x36363636, 0x36363636, 0x36363636, 0x36363636

.balign 32
hmac_opad_const:
  .word 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c
  .word 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c

.balign 32
hmac_bswap32_mask:
  .word 0x000000ff, 0x000000ff, 0x000000ff, 0x000000ff
  .word 0x000000ff, 0x000000ff, 0x000000ff, 0x000000ff

/* Padding word for 768-bit total length (64B key_pad + 32B msg):
   Byte 0: 0x80, Bytes 1..23: 0x00, Length: 768 bits (0x0300) -> 0x00030000 */
.balign 32
hmac_pad_768:
  .word 0x00000080, 0x00000000, 0x00000000, 0x00000000
  .word 0x00000000, 0x00000000, 0x00000000, 0x00030000

/* Standard SHA-256 IV masked with dummy constant 0xABCDEF01 */
.balign 32
hmac_iv_s0:
  .word 0x5be0cd19 ^ 0xABCDEF01
  .word 0x1f83d9ab ^ 0xABCDEF01
  .word 0x9b05688c ^ 0xABCDEF01
  .word 0x510e527f ^ 0xABCDEF01
  .word 0xa54ff53a ^ 0xABCDEF01
  .word 0x3c6ef372 ^ 0xABCDEF01
  .word 0xbb67ae85 ^ 0xABCDEF01
  .word 0x6a09e667 ^ 0xABCDEF01

.balign 32
hmac_iv_s1:
  .word 0xABCDEF01, 0xABCDEF01, 0xABCDEF01, 0xABCDEF01
  .word 0xABCDEF01, 0xABCDEF01, 0xABCDEF01, 0xABCDEF01

.bss
.balign 32
hmac_mbuf_s0: .zero 128
.balign 32
hmac_mbuf_s1: .zero 128

.balign 32
.globl state_s0
state_s0: .zero 32
.balign 32
.globl state_s1
state_s1: .zero 32
