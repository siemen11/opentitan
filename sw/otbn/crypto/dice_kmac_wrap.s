/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * DICE Key Wrapping Envelope using Hardware-Sideloaded KMAC-256.
 *
 * Implements Authenticated Encryption (AEAD) with domain separation:
 *   1. Keystream Derivation:
 *        KS = KMAC-256(Keymgr_Owner_Key, DOM_KS || Nonce) [256 bits]
 *   2. Encryption (Masked XOR):
 *        Ciphertext = CDI_1 ^ KS
 *   3. Authentication Tag Derivation:
 *        Tag = KMAC-256(Keymgr_Owner_Key, DOM_TAG || Nonce || Ciphertext) [256 bits]
 *
 * During unwrapping, Tag is verified in constant time before decryption.
 * CDI_1 is restored directly into 2 Boolean shares without ever exposing
 * the unmasked secret key.
 */

.globl kmac_wrap_cdi1
.globl kmac_unwrap_cdi1

.text

/**
 * Wrap CDI1 using hardware-sideloaded KMAC-256.
 *
 * @param[in]  x10: Pointer to 256-bit CDI1 share 0 (DMEM)
 * @param[in]  x11: Pointer to 256-bit CDI1 share 1 (DMEM)
 * @param[in]  x12: Pointer to 256-bit Nonce (DMEM)
 * @param[out] x13: Pointer to output Wrapped Key struct in DMEM:
 *                    Offset 0:  Nonce (32 bytes)
 *                    Offset 32: Ciphertext (32 bytes)
 *                    Offset 64: Tag (32 bytes)
 *
 * Clobbered registers: x10-x19, x20-x25, x28-x30, w0-w31
 */
kmac_wrap_cdi1:
  /* Save return address and arguments in callee-preserved registers */
  addi     x16, x1, 0
  addi     x17, x10, 0         /* x17 <= ptr cdi1_s0 */
  addi     x18, x11, 0         /* x18 <= ptr cdi1_s1 */
  addi     x19, x12, 0         /* x19 <= ptr nonce */
  addi     x15, x13, 0         /* x15 <= ptr wrapped_out */

  /* Zero register */
  bn.xor   w31, w31, w31

  /* --- Step 1: Keystream Derivation ---
   * Absorb message: DOM_KS (32 bytes) || Nonce (32 bytes) = 64 bytes
   */
  /* Set DOM_KS into wrap_buf + 0 (32 bytes: word 0 = 1, rest 0) */
  la       x2, wrap_buf
  li       x4, 31
  bn.sid   x4, 0(x2)
  li       x4, 1
  sw       x4, 0(x2)

  /* Copy Nonce into wrap_buf + 32 and into output envelope (Offset 0) */
  li       x4, 0
  bn.lid   x4, 0(x19)
  bn.sid   x4, 32(x2)
  bn.sid   x4, 0(x15)

  /* Initialize KMAC-256 session */
  jal      x1, xof_kmac256_init

  /* Absorb 64 bytes */
  li       x20, 64
  la       x21, wrap_buf
  li       x22, 0
  jal      x1, xof_absorb

  /* Process and squeeze 32 bytes of keystream */
  jal      x1, xof_process
  jal      x1, xof_squeeze32
  /* Squeeze result: w29 <= KS_share0, w30 <= KS_share1 */

  /* Close KMAC session */
  jal      x1, xof_finish

  /* --- Step 2: Encrypt CDI1 with Keystream (Masked XOR) --- */
  /* Load CDI1 shares */
  li       x2, 0
  bn.lid   x2, 0(x17)          /* w0 <= cdi1_s0 */
  li       x2, 1
  bn.lid   x2, 0(x18)          /* w1 <= cdi1_s1 */

  /* Masked XOR: ct_s0 = cdi1_s0 ^ ks_s0, ct_s1 = cdi1_s1 ^ ks_s1 */
  bn.xor   w2, w0, w29
  bn.xor   w3, w1, w30

  /* Form public ciphertext for storage: Ciphertext = ct_s0 ^ ct_s1 */
  bn.xor   w4, w2, w3

  /* Write Ciphertext to wrap_buf + 64 (for tag computation) and output (Offset 32) */
  la       x2, wrap_buf
  li       x3, 4
  bn.sid   x3, 64(x2)
  bn.sid   x3, 32(x15)

  /* --- Step 3: Tag Derivation ---
   * Absorb message: DOM_TAG (32 bytes) || Nonce (32 bytes) || Ciphertext (32 bytes) = 96 bytes
   */
  /* Set DOM_TAG into wrap_buf + 0 (32 bytes: word 0 = 2, rest 0) */
  li       x4, 31
  bn.sid   x4, 0(x2)
  li       x4, 2
  sw       x4, 0(x2)

  /* Initialize KMAC-256 session */
  jal      x1, xof_kmac256_init

  /* Absorb 96 bytes */
  li       x20, 96
  la       x21, wrap_buf
  li       x22, 0
  jal      x1, xof_absorb

  /* Process and squeeze 32 bytes of tag */
  jal      x1, xof_process
  jal      x1, xof_squeeze32
  /* Squeeze result: w29 <= Tag_share0, w30 <= Tag_share1 */

  /* Close KMAC session */
  jal      x1, xof_finish

  /* Form unmasked Tag: Tag = tag_s0 ^ tag_s1 */
  bn.xor   w5, w29, w30

  /* Write Tag to output envelope (Offset 64) */
  li       x3, 5
  bn.sid   x3, 64(x15)

  /* --- Step 4: Wipe temporary state --- */
  la       x2, wrap_buf
  li       x3, 31
  bn.sid   x3, 0(x2)
  bn.sid   x3, 32(x2)
  bn.sid   x3, 64(x2)
  bn.sid   x3, 96(x2)
  bn.mov   w0, w31
  bn.mov   w1, w31
  bn.mov   w2, w31
  bn.mov   w3, w31
  bn.mov   w4, w31
  bn.mov   w5, w31
  bn.mov   w29, w31
  bn.mov   w30, w31

  /* Restore return address and return */
  addi     x1, x16, 0
  ret

/**
 * Unwrap CDI1 using hardware-sideloaded KMAC-256 with constant-time verification.
 *
 * @param[in]  x10: Pointer to input Wrapped Key struct in DMEM:
 *                    Offset 0:  Nonce (32 bytes)
 *                    Offset 32: Ciphertext (32 bytes)
 *                    Offset 64: Tag (32 bytes)
 * @param[out] x11: Pointer to destination 256-bit CDI1 share 0 (DMEM)
 * @param[out] x12: Pointer to destination 256-bit CDI1 share 1 (DMEM)
 * @param[out] x10: Return status (0 = SUCCESS, 1 = VERIFICATION_FAILED)
 *
 * Clobbered registers: x10-x19, x20-x25, x28-x30, w0-w31
 */
kmac_unwrap_cdi1:
  /* Save return address and arguments */
  addi     x16, x1, 0
  addi     x15, x10, 0         /* x15 <= ptr wrapped_in */
  addi     x17, x11, 0         /* x17 <= ptr dest cdi1_s0 */
  addi     x18, x12, 0         /* x18 <= ptr dest cdi1_s1 */

  /* Zero register */
  bn.xor   w31, w31, w31

  /* --- Step 1: Compute Expected Tag ---
   * Message: DOM_TAG (32B) || Nonce (32B) || Ciphertext (32B) = 96 bytes
   */
  la       x2, wrap_buf
  li       x4, 31
  bn.sid   x4, 0(x2)
  li       x4, 2
  sw       x4, 0(x2)           /* wrap_buf + 0 <= DOM_TAG */

  /* Copy Nonce and Ciphertext from input envelope into wrap_buf */
  bn.lid   x4, 0(x15)
  bn.sid   x4, 32(x2)          /* wrap_buf + 32 <= Nonce */
  bn.lid   x4, 32(x15)
  bn.sid   x4, 64(x2)          /* wrap_buf + 64 <= Ciphertext */

  /* Initialize KMAC-256 session */
  jal      x1, xof_kmac256_init

  /* Absorb 96 bytes */
  li       x20, 96
  la       x21, wrap_buf
  li       x22, 0
  jal      x1, xof_absorb

  /* Process and squeeze expected tag */
  jal      x1, xof_process
  jal      x1, xof_squeeze32
  jal      x1, xof_finish

  /* Expected tag = w29 ^ w30 */
  bn.xor   w4, w29, w30

  /* --- Step 2: Constant-Time Tag Verification --- */
  /* Load stored Tag from input envelope (Offset 64) */
  li       x3, 5
  bn.lid   x3, 64(x15)         /* w5 <= stored Tag */

  /* w6 <= Expected Tag ^ Stored Tag */
  bn.xor   w6, w4, w5

  /* Check if w6 == 0 using zero flag */
  bn.add   w31, w6, w31        /* Updates FG0 flags based on w6 */
  csrrs    x2, FLAGS, x0       /* Read FLAGS CSR */
  andi     x2, x2, 0x8         /* Isolate Z flag (bit 3) */
  xori     x10, x2, 0x8        /* x10 = 0 if Z=1 (match), x10 = 8 if Z=0 (mismatch) */
  srli     x10, x10, 3         /* x10 = 0 if OK, 1 if mismatch */

  /* If mismatch, branch to verification failure handler */
  bne      x10, x0, _unwrap_fail

  /* --- Step 3: Keystream Derivation & Decryption ---
   * Message: DOM_KS (32B) || Nonce (32B) = 64 bytes
   */
  la       x2, wrap_buf
  li       x4, 31
  bn.sid   x4, 0(x2)
  li       x4, 1
  sw       x4, 0(x2)           /* wrap_buf + 0 <= DOM_KS */
  /* Nonce is already at wrap_buf + 32 */

  /* Initialize KMAC-256 session */
  jal      x1, xof_kmac256_init

  /* Absorb 64 bytes */
  li       x20, 64
  la       x21, wrap_buf
  li       x22, 0
  jal      x1, xof_absorb

  /* Process and squeeze keystream */
  jal      x1, xof_process
  jal      x1, xof_squeeze32
  jal      x1, xof_finish
  /* Result: w29 <= KS_share0, w30 <= KS_share1 */

  /* --- Step 4: Decrypt Ciphertext directly into 2 Shares ---
   * CDI1_share0 = Ciphertext ^ KS_share0
   * CDI1_share1 = KS_share1
   * Note: (Ciphertext ^ KS_share0) ^ KS_share1 = Ciphertext ^ KS = CDI1.
   */
  li       x3, 4
  bn.lid   x3, 32(x15)         /* w4 <= Ciphertext */
  bn.xor   w0, w4, w29         /* w0 <= CDI1_share0 */
  bn.mov   w1, w30             /* w1 <= CDI1_share1 */

  /* Store decrypted shares to destination pointers */
  li       x2, 0
  bn.sid   x2, 0(x17)
  li       x2, 1
  bn.sid   x2, 0(x18)

  /* --- Step 5: Wipe temporary state and return success --- */
  la       x2, wrap_buf
  li       x3, 31
  bn.sid   x3, 0(x2)
  bn.sid   x3, 32(x2)
  bn.sid   x3, 64(x2)
  bn.sid   x3, 96(x2)
  bn.mov   w0, w31
  bn.mov   w1, w31
  bn.mov   w4, w31
  bn.mov   w5, w31
  bn.mov   w6, w31
  bn.mov   w29, w31
  bn.mov   w30, w31

  li       x10, 0              /* Return SUCCESS */
  addi     x1, x16, 0
  ret

_unwrap_fail:
  /* On verification failure: wipe buffer and destination pointers */
  la       x2, wrap_buf
  li       x3, 31
  bn.sid   x3, 0(x2)
  bn.sid   x3, 32(x2)
  bn.sid   x3, 64(x2)
  bn.sid   x3, 96(x2)
  bn.sid   x3, 0(x17)
  bn.sid   x3, 0(x18)
  bn.mov   w4, w31
  bn.mov   w5, w31
  bn.mov   w6, w31
  bn.mov   w29, w31
  bn.mov   w30, w31

  li       x10, 1              /* Return VERIFICATION_FAILED */
  addi     x1, x16, 0
  ret

.bss
.balign 32
wrap_buf:
  .zero 128
