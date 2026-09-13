/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * DICE Attestation & Key Management Application on OTBN.
 *
 * Implements HMAC-based DICE derivations with KMAC hardware key-wrapping:
 *
 * Mode 1 (MODE_CREATOR_STAGE):
 *   1. CDI_0 = HMAC-SHA256(UDS, rom_ext_measurement)
 *   2. CDI_1 = HMAC-SHA256(CDI_0, bl0_measurement)
 *   3. Optional synchronization point (WFI) for Keymgr state advance
 *   4. Wrapped_Key = kmac_wrap_cdi1(CDI_1, Nonce) using KMAC AppKMAC sideloaded key
 *
 * Mode 2 (MODE_BL0_UNWRAP):
 *   1. Unwraps CDI_1 from Flash envelope (Nonce || Ciphertext || Tag)
 *   2. Constant-time tag verification
 *   3. Decrypts directly into 2 Boolean shares in OTBN DMEM
 */

.section .text
.globl main
.globl run_creator_stage
.globl run_bl0_unwrap

main:
  /* Zero register */
  bn.xor   w31, w31, w31

  /* Read operating mode */
  la       x2, mode
  lw       x2, 0(x2)

  li       x3, 1
  beq      x2, x3, _call_creator

  li       x3, 2
  beq      x2, x3, _call_unwrap

  li       x3, 3
  beq      x2, x3, _call_p256_cdi0

  li       x3, 4
  beq      x2, x3, _call_p256_cdi1

  li       x3, 5
  beq      x2, x3, _call_unwrap_and_keygen

  /* Unknown mode: fail */
  li       x2, 0xff
  la       x3, status
  sw       x2, 0(x3)
  ecall

_call_creator:
  jal      x1, run_creator_stage
  ecall

_call_unwrap:
  jal      x1, run_bl0_unwrap
  ecall

_call_p256_cdi0:
  jal      x1, run_p256_cdi0
  ecall

_call_p256_cdi1:
  jal      x1, run_p256_cdi1
  ecall

_call_unwrap_and_keygen:
  jal      x1, run_bl0_unwrap_and_keygen
  ecall

/**
 * Mode 1: Creator Stage (ROM_EXT)
 */
run_creator_stage:
  /* Save return address */
  addi     x26, x1, 0

  /* Zero register */
  bn.xor   w31, w31, w31

  /* Check if UDS is supplied in DMEM. If not, pull from sideloaded WSRs KEY_S0_L / KEY_S1_L */
  la       x2, uds_s0
  lw       x3, 0(x2)
  bne      x3, x0, _uds_ready
  li       x3, 0
  bn.wsrr  w0, KEY_S0_L
  bn.sid   x3, 0(x2)
  la       x2, uds_s1
  bn.wsrr  w0, KEY_S1_L
  bn.sid   x3, 0(x2)
_uds_ready:

  /* Step 1: CDI_0 = NIST SP 800-108 Counter Mode KDF(UDS, rom_ext_kdf) */
  la       x10, uds_s0
  la       x11, uds_s1
  la       x12, rom_ext_kdf_s0
  la       x13, rom_ext_kdf_s1
  la       x14, cdi0_s0
  la       x15, cdi0_s1
  jal      x1, hmac_sha256_kdf_masked

  /* Step 2: Generate CDI_0 P-256 Public Key (x, y) */
  jal      x1, run_p256_cdi0

  /* Step 3: CDI_1 = NIST SP 800-108 Counter Mode KDF(CDI_0, bl0_kdf) */
  la       x10, cdi0_s0
  la       x11, cdi0_s1
  la       x12, bl0_kdf_s0
  la       x13, bl0_kdf_s1
  la       x14, cdi1_s0
  la       x15, cdi1_s1
  jal      x1, hmac_sha256_kdf_masked

  /* Step 4: Check if WFI pause is requested for Keymgr advance synchronization */
  la       x2, wfi_enable
  lw       x2, 0(x2)
  beq      x2, x0, _skip_wfi
  wfi
_skip_wfi:

  /* Step 5: Wrap CDI_1 using hardware KMAC in AppKMAC mode */
  la       x10, cdi1_s0
  la       x11, cdi1_s1
  la       x12, nonce
  la       x13, wrapped_key
  jal      x1, kmac_wrap_cdi1

  /* Success: status = 0 */
  la       x2, status
  sw       x0, 0(x2)

  addi     x1, x26, 0
  ret

/**
 * P-256 Public Key generation from CDI_0
 */
run_p256_cdi0:
  addi     x25, x1, 0

  bn.xor   w31, w31, w31
  li       x2, 20
  la       x3, cdi0_s0
  bn.lid   x2, 0(x3)
  bn.mov   w21, w31
  li       x2, 10
  la       x3, cdi0_s1
  bn.lid   x2, 0(x3)
  bn.mov   w11, w31

  jal      x1, p256_key_from_seed

  /* Store d0, d1 */
  li       x2, 20
  la       x3, d0
  bn.sid   x2, 0(x3++)
  li       x2, 21
  bn.sid   x2, 0(x3)
  li       x2, 10
  la       x3, d1
  bn.sid   x2, 0(x3++)
  li       x2, 11
  bn.sid   x2, 0(x3)

  /* Compute public key d*G and store in x, y */
  jal      x1, p256_base_mult

  /* Validate point on curve */
  jal      x1, p256_isoncurve
  bn.cmp   w18, w19
  jal      x1, trigger_fault_if_fg0_z

  addi     x1, x25, 0
  ret

/**
 * Mode 2: BL0 Unwrap Stage (Unwrap Only)
 */
run_bl0_unwrap:
  /* Save return address */
  addi     x26, x1, 0

  /* Zero register */
  bn.xor   w31, w31, w31

  /* Unwrap CDI_1 from Flash envelope */
  la       x10, wrapped_key
  la       x11, cdi1_s0
  la       x12, cdi1_s1
  jal      x1, kmac_unwrap_cdi1

  /* Store unwrap status (0 = SUCCESS, 1 = VERIFICATION_FAILED) */
  la       x2, status
  sw       x10, 0(x2)

  addi     x1, x26, 0
  ret

/**
 * Mode 4: P-256 Keypair generation from CDI_1
 */
run_p256_cdi1:
  addi     x25, x1, 0

  /* Generate BL0 keypair from CDI_1 shares */
  bn.xor   w31, w31, w31
  li       x2, 20
  la       x3, cdi1_s0
  bn.lid   x2, 0(x3)
  bn.mov   w21, w31
  li       x2, 10
  la       x3, cdi1_s1
  bn.lid   x2, 0(x3)
  bn.mov   w11, w31

  jal      x1, p256_key_from_seed

  /* Store d0, d1 to DMEM */
  li       x2, 20
  la       x3, d0
  bn.sid   x2, 0(x3++)
  li       x2, 21
  bn.sid   x2, 0(x3)
  li       x2, 10
  la       x3, d1
  bn.sid   x2, 0(x3++)
  li       x2, 11
  bn.sid   x2, 0(x3)

  /* Compute public key d*G and store in x, y */
  jal      x1, p256_base_mult

  /* Validate point on curve */
  jal      x1, p256_isoncurve
  bn.cmp   w18, w19
  jal      x1, trigger_fault_if_fg0_z

  addi     x1, x25, 0
  ret

/**
 * Mode 5: BL0 Unwrap and Keypair Generation
 */
run_bl0_unwrap_and_keygen:
  addi     x24, x1, 0
  jal      x1, run_bl0_unwrap
  la       x2, status
  lw       x2, 0(x2)
  bne      x2, x0, _unwrap_keygen_fail
  jal      x1, run_p256_cdi1
_unwrap_keygen_fail:
  addi     x1, x24, 0
  ret


.data

/* No pre-initialized data required in dice_chain_app itself */

.bss

.balign 4
.globl mode
mode:
  .zero 4

.balign 4
.globl wfi_enable
wfi_enable:
  .zero 4

.balign 4
.globl status
status:
  .zero 4

/* UDS Root Key (2 shares) */
.balign 32
.globl uds_s0
uds_s0:
  .zero 32
.balign 32
.globl uds_s1
uds_s1:
  .zero 32

/* ROM_EXT SP 800-108 KDF Message Block (64 bytes, 2 shares) */
.balign 32
.globl rom_ext_kdf_s0
rom_ext_kdf_s0:
  .zero 64
.balign 32
.globl rom_ext_kdf_s1
rom_ext_kdf_s1:
  .zero 64

/* BL0 SP 800-108 KDF Message Block (64 bytes, 2 shares) */
.balign 32
.globl bl0_kdf_s0
bl0_kdf_s0:
  .zero 64
.balign 32
.globl bl0_kdf_s1
bl0_kdf_s1:
  .zero 64

/* 256-bit Nonce for Key Wrapping */
.balign 32
.globl nonce
nonce:
  .zero 32

/* Derived CDI_0 (2 shares) */
.balign 32
.globl cdi0_s0
cdi0_s0:
  .zero 32
.balign 32
.globl cdi0_s1
cdi0_s1:
  .zero 32

/* Derived / Unwrapped CDI_1 (2 shares) */
.balign 32
.globl cdi1_s0
cdi1_s0:
  .zero 32
.balign 32
.globl cdi1_s1
cdi1_s1:
  .zero 32

/* Wrapped Key Envelope (Nonce[32] || Ciphertext[32] || Tag[32] = 96 bytes) */
.balign 32
.globl wrapped_key
wrapped_key:
  .zero 96

/* First share of private key scalar (320 bits + padding) */
.balign 32
.globl d0
d0:
  .zero 64

/* Second share of private key scalar (320 bits + padding) */
.balign 32
.globl d1
d1:
  .zero 64

/* Public key x coordinate (256 bits) */
.balign 32
.globl x
x:
  .zero 32

/* Public key y coordinate (256 bits) */
.balign 32
.globl y
y:
  .zero 32
