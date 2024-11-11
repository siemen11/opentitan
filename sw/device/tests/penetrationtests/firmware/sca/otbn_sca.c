// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/tests/penetrationtests/firmware/sca/otbn_sca.h"

#include "ecc256_keygen_sca.h"
#include "sw/device/lib/arch/boot_stage.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/crypto/drivers/keymgr.h"
#include "sw/device/lib/crypto/impl/keyblob.h"
#include "sw/device/lib/crypto/impl/status.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/keymgr_testutils.h"
#include "sw/device/lib/testing/test_framework/ottf_test_config.h"
#include "sw/device/lib/testing/test_framework/ujson_ottf.h"
#include "sw/device/lib/ujson/ujson.h"
#include "sw/device/sca/lib/prng.h"
#include "sw/device/sca/lib/sca.h"
#include "sw/device/tests/penetrationtests/firmware/lib/sca_lib.h"
#include "sw/device/tests/penetrationtests/json/otbn_sca_commands.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "otbn_regs.h"  // Generated.

static dif_otbn_t otbn;
static dif_keymgr_t keymgr;
static dif_kmac_t kmac;

// NOP macros.
#define NOP1 "addi x0, x0, 0\n"
#define NOP10 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1
#define NOP30 NOP10 NOP10 NOP10

enum {
  kKeySideloadNumIt = 16,
  /**
   * Number of bytes for ECDSA P-256 private keys, message digests, and point
   * coordinates.
   */
  kEcc256NumBytes = 256 / 8,
  /**
   * Number of 32b words for ECDSA P-256 private keys, message digests, and
   * point coordinates.
   */
  kEcc256NumWords = kEcc256NumBytes / sizeof(uint32_t),
};

// Data structs for key sideloading test.
OTBN_DECLARE_APP_SYMBOLS(otbn_key_sideload_sca);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload_sca, k_s0_l);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload_sca, k_s0_h);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload_sca, k_s1_l);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload_sca, k_s1_h);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload_sca, k_l);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload_sca, k_h);
const otbn_app_t kOtbnAppKeySideloadSca =
    OTBN_APP_T_INIT(otbn_key_sideload_sca);
static const otbn_addr_t kOtbnAppKeySideloadks0l =
    OTBN_ADDR_T_INIT(otbn_key_sideload_sca, k_s0_l);
static const otbn_addr_t kOtbnAppKeySideloadks0h =
    OTBN_ADDR_T_INIT(otbn_key_sideload_sca, k_s0_h);
static const otbn_addr_t kOtbnAppKeySideloadks1l =
    OTBN_ADDR_T_INIT(otbn_key_sideload_sca, k_s1_l);
static const otbn_addr_t kOtbnAppKeySideloadks1h =
    OTBN_ADDR_T_INIT(otbn_key_sideload_sca, k_s1_h);
static const otbn_addr_t kOtbnAppKeySideloadkl =
    OTBN_ADDR_T_INIT(otbn_key_sideload_sca, k_l);
static const otbn_addr_t kOtbnAppKeySideloadkh =
    OTBN_ADDR_T_INIT(otbn_key_sideload_sca, k_h);

// RSA OTBN App.
OTBN_DECLARE_APP_SYMBOLS(rsa);
OTBN_DECLARE_SYMBOL_ADDR(rsa, mode);
OTBN_DECLARE_SYMBOL_ADDR(rsa, n_limbs);
OTBN_DECLARE_SYMBOL_ADDR(rsa, inout);
OTBN_DECLARE_SYMBOL_ADDR(rsa, modulus);
OTBN_DECLARE_SYMBOL_ADDR(rsa, exp);

static const otbn_app_t kOtbnAppRsa = OTBN_APP_T_INIT(rsa);
static const otbn_addr_t kOtbnVarRsaMode = OTBN_ADDR_T_INIT(rsa, mode);
static const otbn_addr_t kOtbnVarRsaNLimbs = OTBN_ADDR_T_INIT(rsa, n_limbs);
static const otbn_addr_t kOtbnVarRsaInOut = OTBN_ADDR_T_INIT(rsa, inout);
static const otbn_addr_t kOtbnVarRsaModulus = OTBN_ADDR_T_INIT(rsa, modulus);
static const otbn_addr_t kOtbnVarRsaExp = OTBN_ADDR_T_INIT(rsa, exp);

// INSN Carry Flag OTBN App.
OTBN_DECLARE_APP_SYMBOLS(otbn_insn_carry_flag);
OTBN_DECLARE_SYMBOL_ADDR(otbn_insn_carry_flag, big_num);
OTBN_DECLARE_SYMBOL_ADDR(otbn_insn_carry_flag, big_num_out);

static const otbn_app_t kOtbnAppInsnCarryFlag = OTBN_APP_T_INIT(otbn_insn_carry_flag);
static const otbn_addr_t kOtbnVarInsnCarryFlagBigNum = OTBN_ADDR_T_INIT(otbn_insn_carry_flag, big_num);
static const otbn_addr_t kOtbnVarInsnCarryFlagBigNumOut = OTBN_ADDR_T_INIT(otbn_insn_carry_flag, big_num_out);

// p256_ecdsa_sca has randomnization removed.
OTBN_DECLARE_APP_SYMBOLS(p256_ecdsa_sca);

OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, mode);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, msg);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, r);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, s);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, x);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, y);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, d0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, d1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, k0);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, k1);
OTBN_DECLARE_SYMBOL_ADDR(p256_ecdsa_sca, x_r);

static const otbn_app_t kOtbnAppP256Ecdsa = OTBN_APP_T_INIT(p256_ecdsa_sca);

static const otbn_addr_t kOtbnVarMode = OTBN_ADDR_T_INIT(p256_ecdsa_sca, mode);
static const otbn_addr_t kOtbnVarMsg = OTBN_ADDR_T_INIT(p256_ecdsa_sca, msg);
static const otbn_addr_t kOtbnVarR = OTBN_ADDR_T_INIT(p256_ecdsa_sca, r);
static const otbn_addr_t kOtbnVarS = OTBN_ADDR_T_INIT(p256_ecdsa_sca, s);
static const otbn_addr_t kOtbnVarD0 = OTBN_ADDR_T_INIT(p256_ecdsa_sca, d0);
static const otbn_addr_t kOtbnVarD1 = OTBN_ADDR_T_INIT(p256_ecdsa_sca, d1);
static const otbn_addr_t kOtbnVarK0 = OTBN_ADDR_T_INIT(p256_ecdsa_sca, k0);
static const otbn_addr_t kOtbnVarK1 = OTBN_ADDR_T_INIT(p256_ecdsa_sca, k1);

/**
 * Clears the OTBN DMEM and IMEM.
 *
 * @returns OK or error.
 */
static status_t clear_otbn(void) {
  // Clear OTBN memory.
  TRY(otbn_dmem_sec_wipe());
  TRY(otbn_imem_sec_wipe());

  return OK_STATUS();
}

/**
 * Signs a message with ECDSA using the P-256 curve.
 *
 * R = k*G
 * r = x-coordinate of R
 * s = k^(-1)(msg + r*d)  mod n
 *
 * @param otbn_ctx            The OTBN context object.
 * @param msg                 The message to sign, msg (32B).
 * @param private_key_d       The private key, d (32B).
 * @param k                   The ephemeral key,  k (random scalar) (32B).
 * @param[out] signature_r    Signature component r (the x-coordinate of R).
 *                            Provide a pre-allocated 32B buffer.
 * @param[out] signature_s    Signature component s (the proof).
 *                            Provide a pre-allocated 32B buffer.
 */
static status_t p256_ecdsa_sign(const uint32_t *msg, const uint32_t *private_key_d,
                            uint32_t *signature_r, uint32_t *signature_s,
                            const uint32_t *k) {
  uint32_t mode = 1;  // mode 1 => sign
  // Send operation mode to OTBN
  TRY(otbn_dmem_write(/*num_words=*/1, &mode, kOtbnVarMode));
  // Send Msg to OTBN
  TRY(otbn_dmem_write(kEcc256NumWords, msg, kOtbnVarMsg));
  // Send two shares of private_key_d to OTBN
  TRY(otbn_dmem_write(kEcc256NumWords, private_key_d, kOtbnVarD0));
  TRY(otbn_dmem_write(kEcc256NumWords, private_key_d + kEcc256NumWords, kOtbnVarD1));
  // Send two shares of secret_k to OTBN
  TRY(otbn_dmem_write(kEcc256NumWords, k, kOtbnVarK0));
  TRY(otbn_dmem_write(kEcc256NumWords, k + kEcc256NumWords, kOtbnVarK1));

  // Start OTBN execution
  sca_set_trigger_high();
  // Give the trigger time to rise.
  asm volatile(NOP30);
  otbn_execute();
  otbn_busy_wait_for_done();
  sca_set_trigger_low();

  // Read the results back (sig_r, sig_s)
  TRY(otbn_dmem_read(kEcc256NumWords, kOtbnVarR, signature_r));
  TRY(otbn_dmem_read(kEcc256NumWords, kOtbnVarS, signature_s));

  return OK_STATUS();
}

status_t handle_otbn_sca_ecdsa_p256_sign(ujson_t *uj) {
  // Get message and key.
  penetrationtest_otbn_sca_ecdsa_p256_sign_t uj_data;
  TRY(ujson_deserialize_penetrationtest_otbn_sca_ecdsa_p256_sign_t(uj, &uj_data));

  uint32_t ecc256_private_key_d[2 * kEcc256NumWords];
  memset(ecc256_private_key_d, 0, sizeof(ecc256_private_key_d));
  memcpy(ecc256_private_key_d, uj_data.d0, sizeof(uj_data.d0));
  memcpy(ecc256_private_key_d + kEcc256NumWords, uj_data.d1, sizeof(uj_data.d1));

  uint32_t ecc256_secret_k[2 * kEcc256NumWords];
  memset(ecc256_secret_k, 0, sizeof(ecc256_secret_k));
  memcpy(ecc256_secret_k, uj_data.k0, sizeof(uj_data.k0));
  memcpy(ecc256_secret_k + kEcc256NumWords, uj_data.k1, sizeof(uj_data.k1));

  otbn_load_app(kOtbnAppP256Ecdsa);

  // Signature output.
  uint32_t ecc256_signature_r[kEcc256NumWords];
  uint32_t ecc256_signature_s[kEcc256NumWords];

  // Start the operation.
  p256_ecdsa_sign(uj_data.msg, ecc256_private_key_d, ecc256_signature_r, ecc256_signature_s, ecc256_secret_k);

  // Send back signature to host.
  penetrationtest_otbn_sca_ecdsa_p256_signature_t uj_output;
  memcpy(uj_output.r, ecc256_signature_r, sizeof(ecc256_signature_r));
  memcpy(uj_output.s, ecc256_signature_s, sizeof(ecc256_signature_s));
  RESP_OK(ujson_serialize_penetrationtest_otbn_sca_ecdsa_p256_signature_t, uj, &uj_output);

  // Clear OTBN memory
  TRY(clear_otbn());

  return OK_STATUS();
}

status_t handle_otbn_sca_rsa512_decrypt(ujson_t *uj) {
  // Get RSA256 parameters.
  penetrationtest_otbn_sca_rsa512_dec_t uj_data;
  TRY(ujson_deserialize_penetrationtest_otbn_sca_rsa512_dec_t(uj, &uj_data));

  otbn_load_app(kOtbnAppRsa);

  uint32_t mode = 2; // Decrypt.
  // RSA512 configuration.
  uint32_t n_limbs = 2;

  // Write data into OTBN DMEM.
  TRY(dif_otbn_dmem_write(&otbn, kOtbnVarRsaMode, &mode, sizeof(mode)));
  TRY(dif_otbn_dmem_write(&otbn, kOtbnVarRsaNLimbs, &n_limbs, sizeof(n_limbs)));
  TRY(dif_otbn_dmem_write(&otbn, kOtbnVarRsaModulus, uj_data.mod, sizeof(uj_data.mod)));
  TRY(dif_otbn_dmem_write(&otbn, kOtbnVarRsaExp, uj_data.exp, sizeof(uj_data.exp)));
  TRY(dif_otbn_dmem_write(&otbn, kOtbnVarRsaInOut, uj_data.msg, sizeof(uj_data.msg)));

  sca_set_trigger_high();
  // Give the trigger time to rise.
  asm volatile(NOP30);
  otbn_execute();
  otbn_busy_wait_for_done();
  sca_set_trigger_low();

  // Send back decryption result to host.
  penetrationtest_otbn_sca_rsa512_dec_out_t uj_output;
  TRY(dif_otbn_dmem_read(&otbn, kOtbnVarRsaInOut, uj_output.out, sizeof(uj_output.out)));
  RESP_OK(ujson_serialize_penetrationtest_otbn_sca_rsa512_dec_out_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_otbn_sca_key_sideload_fvsr(ujson_t *uj) {
  // Get fixed seed.
  penetrationtest_otbn_sca_fixed_seed_t uj_data;
  TRY(ujson_deserialize_penetrationtest_otbn_sca_fixed_seed_t(uj, &uj_data));

  // Key generation parameters.
  dif_keymgr_versioned_key_params_t sideload_params[kKeySideloadNumIt];

  // Generate FvsR values.
  bool sample_fixed = true;
  for (size_t it = 0; it < kKeySideloadNumIt; it++) {
    sideload_params[it].version = 0x0;
    sideload_params[it].dest = kDifKeymgrVersionedKeyDestOtbn;
    memset(sideload_params[it].salt, 0, sizeof(sideload_params[it].salt));
    if (sample_fixed) {
      sideload_params[it].salt[0] = uj_data.fixed_seed;
    } else {
      sideload_params[it].salt[0] = prng_rand_uint32();
    }
    sample_fixed = prng_rand_uint32() & 0x1;
  }

  otbn_load_app(kOtbnAppKeySideloadSca);

  uint32_t key_share_0_l[kKeySideloadNumIt], key_share_0_h[kKeySideloadNumIt];
  uint32_t key_share_1_l[16], key_share_1_h[kKeySideloadNumIt];
  uint32_t key_l[kKeySideloadNumIt], key_h[kKeySideloadNumIt];

  // SCA code target.
  for (size_t it = 0; it < kKeySideloadNumIt; it++) {
    TRY(keymgr_testutils_generate_versioned_key(&keymgr, sideload_params[it]));

    TRY(dif_otbn_set_ctrl_software_errs_fatal(&otbn, /*enable=*/false));

    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    otbn_execute();
    otbn_busy_wait_for_done();
    sca_set_trigger_low();
    asm volatile(NOP30);

    otbn_dmem_read(1, kOtbnAppKeySideloadks0l, &key_share_0_l[it]);
    otbn_dmem_read(1, kOtbnAppKeySideloadks0h, &key_share_0_h[it]);
    otbn_dmem_read(1, kOtbnAppKeySideloadks1l, &key_share_1_l[it]);
    otbn_dmem_read(1, kOtbnAppKeySideloadks1h, &key_share_1_h[it]);
    otbn_dmem_read(1, kOtbnAppKeySideloadkl, &key_l[it]);
    otbn_dmem_read(1, kOtbnAppKeySideloadkh, &key_h[it]);
  }

  // Write back shares and keys to host.
  penetrationtest_otbn_sca_key_t uj_output;
  for (size_t it = 0; it < kKeySideloadNumIt; it++) {
    uj_output.shares[0] = key_share_0_l[it];
    uj_output.shares[1] = key_share_0_h[it];
    uj_output.shares[2] = key_share_1_l[it];
    uj_output.shares[3] = key_share_1_h[it];
    uj_output.keys[0] = key_l[it];
    uj_output.keys[1] = key_h[it];
    RESP_OK(ujson_serialize_penetrationtest_otbn_sca_key_t, uj, &uj_output);
  }

  return OK_STATUS();
}

status_t handle_otbn_sca_insn_carry_flag(ujson_t *uj) {
  // Get big number (256 bit).
  penetrationtest_otbn_sca_big_num_t uj_data;
  TRY(ujson_deserialize_penetrationtest_otbn_sca_big_num_t(uj, &uj_data));

  // Load app and write received big_num into DMEM.
  otbn_load_app(kOtbnAppInsnCarryFlag);
  TRY(dif_otbn_dmem_write(&otbn, kOtbnVarInsnCarryFlagBigNum, uj_data.big_num, sizeof(uj_data.big_num)));

  sca_set_trigger_high();
  otbn_execute();
  otbn_busy_wait_for_done();
  sca_set_trigger_low();

  penetrationtest_otbn_sca_big_num_t uj_output;
  memset(uj_output.big_num, 0, sizeof(uj_output.big_num));
  TRY(dif_otbn_dmem_read(&otbn, kOtbnVarInsnCarryFlagBigNumOut, uj_output.big_num, sizeof(uj_output.big_num)));

  RESP_OK(ujson_serialize_penetrationtest_otbn_sca_big_num_t, uj, &uj_output);

  return OK_STATUS();
}

status_t handle_otbn_sca_init_keymgr(ujson_t *uj) {
  if (kBootStage != kBootStageOwner) {
    TRY(keymgr_testutils_startup(&keymgr, &kmac));
    // Advance to OwnerIntermediateKey state.
    TRY(keymgr_testutils_advance_state(&keymgr, &kOwnerIntParams));
    TRY(keymgr_testutils_check_state(&keymgr,
                                     kDifKeymgrStateOwnerIntermediateKey));
    LOG_INFO("Keymgr entered OwnerIntKey State");
  } else {
    TRY(dif_keymgr_init(mmio_region_from_addr(TOP_EARLGREY_KEYMGR_BASE_ADDR),
                        &keymgr));
    TRY(keymgr_testutils_check_state(&keymgr, kDifKeymgrStateOwnerRootKey));
  }

  dif_otbn_t otbn;
  TRY(dif_otbn_init(mmio_region_from_addr(TOP_EARLGREY_OTBN_BASE_ADDR), &otbn));

  return OK_STATUS();
}

status_t handle_otbn_sca_init(ujson_t *uj) {
  // Configure the entropy complex for OTBN. Set the reseed interval to max
  // to avoid a non-constant trigger window.
  TRY(sca_configure_entropy_source_max_reseed_interval());

  sca_init(kScaTriggerSourceOtbn, kScaPeripheralEntropy | kScaPeripheralIoDiv4 |
                                      kScaPeripheralOtbn | kScaPeripheralCsrng |
                                      kScaPeripheralEdn | kScaPeripheralHmac |
                                      kScaPeripheralKmac);

  // Init the OTBN core.
  TRY(dif_otbn_init(mmio_region_from_addr(TOP_EARLGREY_OTBN_BASE_ADDR), &otbn));

  // Load p256 keygen from seed app into OTBN.
  if (otbn_load_app(kOtbnAppP256KeyFromSeed).value != OTCRYPTO_OK.value) {
    return ABORTED();
  }

  // Disable the instruction cache and dummy instructions for better SCA
  // measurements.
  sca_configure_cpu();

  // Read device ID and return to host.
  penetrationtest_device_id_t uj_output;
  TRY(sca_read_device_id(uj_output.device_id));
  RESP_OK(ujson_serialize_penetrationtest_device_id_t, uj, &uj_output);

  return OK_STATUS();
}

status_t handle_otbn_sca(ujson_t *uj) {
  otbn_sca_subcommand_t cmd;
  TRY(ujson_deserialize_otbn_sca_subcommand_t(uj, &cmd));
  switch (cmd) {
    case kOtbnScaSubcommandInit:
      return handle_otbn_sca_init(uj);
    case kOtbnScaSubcommandInitKeyMgr:
      return handle_otbn_sca_init_keymgr(uj);
    case kOtbnScaSubcommandInsnCarryFlag:
      return handle_otbn_sca_insn_carry_flag(uj);
    case kOtbnScaSubcommandEcc256EcdsaKeygenFvsrSeedBatch:
      return handle_otbn_sca_ecc256_ecdsa_keygen_fvsr_seed_batch(uj);
    case kOtbnScaSubcommandEcc256EcdsaKeygenFvsrKeyBatch:
      return handle_otbn_sca_ecc256_ecdsa_keygen_fvsr_key_batch(uj);
    case kOtbnScaSubcommandEcc256SetSeed:
      return handle_otbn_sca_ecc256_set_seed(uj);
    case kOtbnScaSubcommandEcc256SetC:
      return handle_otbn_sca_ecc256_set_c(uj);
    case kOtbnScaSubcommandEcc256EnMasks:
      return handle_otbn_sca_ecc256_en_masks(uj);
    case kOtbnScaSubcommandKeySideloadFvsr:
      return handle_otbn_sca_key_sideload_fvsr(uj);
    case kOtbnScaSubcommandRsa512Decrypt:
      return handle_otbn_sca_rsa512_decrypt(uj);
    case kOtbnScaSubcommandEcdsaP256Sign:
      return handle_otbn_sca_ecdsa_p256_sign(uj);
    case kOtbnScaSubcommandEcdsaP256SignBatch:
      return handle_otbn_sca_ecdsa_p256_sign(uj);
    default:
      LOG_ERROR("Unrecognized OTBN SCA subcommand: %d", cmd);
      return INVALID_ARGUMENT();
  }
  return OK_STATUS();
}
