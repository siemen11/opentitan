// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/tests/penetrationtests/firmware/sca/otbn_sca.h"

#include "ecc256_keygen_sca.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/crypto/drivers/keymgr.h"
#include "sw/device/lib/crypto/impl/keyblob.h"
#include "sw/device/lib/crypto/impl/status.h"
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

// NOP macros.
#define NOP1 "addi x0, x0, 0\n"
#define NOP10 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1
#define NOP30 NOP10 NOP10 NOP10

// Data structs for key sideloading test.
OTBN_DECLARE_APP_SYMBOLS(otbn_key_sideload);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload, k_s0_l);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload, k_s0_h);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload, k_s1_l);
OTBN_DECLARE_SYMBOL_ADDR(otbn_key_sideload, k_s1_h);
const otbn_app_t kOtbnAppKeySideloadSCA = OTBN_APP_T_INIT(otbn_key_sideload);
static const otbn_addr_t kOtbnAppKeySideloadScaks0l =
    OTBN_ADDR_T_INIT(otbn_key_sideload, k_s0_l);
static const otbn_addr_t kOtbnAppKeySideloadScaks0h =
    OTBN_ADDR_T_INIT(otbn_key_sideload, k_s0_h);
static const otbn_addr_t kOtbnAppKeySideloadScaks1l =
    OTBN_ADDR_T_INIT(otbn_key_sideload, k_s1_l);
static const otbn_addr_t kOtbnAppKeySideloadScaks1h =
    OTBN_ADDR_T_INIT(otbn_key_sideload, k_s1_h);

static const otcrypto_key_config_t kPrivateKeyConfig = {
    .version = kOtcryptoLibVersion1,
    .key_mode = kOtcryptoKeyModeEcdsa,
    .key_length = 256 / 8,
    .hw_backed = kHardenedBoolTrue,
    .security_level = kOtcryptoKeySecurityLevelLow,
};

status_t handle_otbn_sca_key_sideload_fvsr(ujson_t *uj) {
  // Get fixed data.
  penetrationtest_otbn_sca_fixed_key_t uj_data;
  TRY(ujson_deserialize_penetrationtest_otbn_sca_fixed_key_t(uj, &uj_data));

  // Data buffers.
  uint32_t key_buffer[16];

  uint32_t key_share_0_l[16];
  uint32_t key_share_0_h[16];
  uint32_t key_share_1_l[16];
  uint32_t key_share_1_h[16];

  // Generate FvsR values.
  bool sample_fixed = true;
  for (size_t it = 0; it < 16; it++) {
    if (sample_fixed) {
      key_buffer[it] = uj_data.fixed_key;
    } else {
      key_buffer[it] = prng_rand_uint32();
    }
    sample_fixed = prng_rand_uint32() & 0x1;
  }
  keymgr_diversification_t diversification;
  // SCA code target.
  for (size_t it = 0; it < 16; it++) {
    otcrypto_blinded_key_t blinded_key = {
        .config = kPrivateKeyConfig,
        .keyblob_length = sizeof(key_buffer[it]),
        .keyblob = &key_buffer[it],
    };
    TRY(keyblob_to_keymgr_diversification(&blinded_key, &diversification));
    otbn_load_app(kOtbnAppKeySideloadSCA);
    sca_set_trigger_high();
    // Give the trigger time to rise.
    asm volatile(NOP30);
    TRY(keymgr_generate_key_otbn(diversification));
    otbn_execute();
    otbn_busy_wait_for_done();
    sca_set_trigger_low();
    asm volatile(NOP30);
    otbn_dmem_read(1, kOtbnAppKeySideloadScaks0l, &key_share_0_l[it]);
    otbn_dmem_read(1, kOtbnAppKeySideloadScaks0h, &key_share_0_h[it]);
    otbn_dmem_read(1, kOtbnAppKeySideloadScaks1l, &key_share_1_l[it]);
    otbn_dmem_read(1, kOtbnAppKeySideloadScaks1h, &key_share_1_h[it]);
  }

  // Write back keys to host.
  penetrationtest_otbn_sca_key_t uj_output;
  for (size_t it = 0; it < 16; it++) {
    uj_output.key[0] = key_share_0_l[it];
    uj_output.key[1] = key_share_0_h[it];
    uj_output.key[2] = key_share_1_l[it];
    uj_output.key[3] = key_share_1_h[it];
    RESP_OK(ujson_serialize_penetrationtest_otbn_sca_key_t, uj, &uj_output);
  }

  return OK_STATUS();
}

status_t handle_otbn_sca_init_keymgr(ujson_t *uj) {
  dif_keymgr_t keymgr;
  dif_kmac_t kmac;
  TRY(keymgr_testutils_startup(&keymgr, &kmac));
  TRY(keymgr_testutils_advance_state(&keymgr, &kOwnerIntParams));
  TRY(keymgr_testutils_advance_state(&keymgr, &kOwnerRootKeyParams));
  TRY(keymgr_testutils_check_state(&keymgr, kDifKeymgrStateOwnerRootKey));

  return OK_STATUS();
}

status_t handle_otbn_sca_init(ujson_t *uj) {
  // Configure the entropy complex for OTBN. Set the reseed interval to max
  // to avoid a non-constant trigger window.
  TRY(sca_configure_entropy_source_max_reseed_interval());

  sca_init(kScaTriggerSourceOtbn, kScaPeripheralEntropy | kScaPeripheralIoDiv4 |
                                      kScaPeripheralOtbn | kScaPeripheralCsrng |
                                      kScaPeripheralEdn | kScaPeripheralHmac);

  // Load p256 keygen from seed app into OTBN.
  if (otbn_load_app(kOtbnAppP256KeyFromSeed).value != OTCRYPTO_OK.value) {
    return ABORTED();
  }

  // Disable the instruction cache and dummy instructions for better SCA
  // measurements.
  sca_configure_cpu();

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
    default:
      LOG_ERROR("Unrecognized OTBN SCA subcommand: %d", cmd);
      return INVALID_ARGUMENT();
  }
  return OK_STATUS();
}
