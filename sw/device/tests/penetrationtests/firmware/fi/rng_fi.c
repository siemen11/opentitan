// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_csrng.h"
#include "sw/device/lib/dif/dif_csrng_shared.h"
#include "sw/device/lib/dif/dif_edn.h"
#include "sw/device/lib/dif/dif_entropy_src.h"
#include "sw/device/lib/dif/dif_rv_core_ibex.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/csrng_testutils.h"
#include "sw/device/lib/testing/edn_testutils.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/rv_core_ibex_testutils.h"
#include "sw/device/lib/testing/test_framework/ujson_ottf.h"
#include "sw/device/lib/ujson/ujson.h"
#include "sw/device/sca/lib/sca.h"
#include "sw/device/tests/penetrationtests/firmware/lib/sca_lib.h"
#include "sw/device/tests/penetrationtests/json/rng_fi_commands.h"

#include "edn_regs.h"  // Generated
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

// NOP macros.
#define NOP1 "addi x0, x0, 0\n"
#define NOP10 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1 NOP1
#define NOP30 NOP10 NOP10 NOP10

enum {
  kEdnKatTimeout = (10 * 1000 * 1000),
  kCsrngExpectedOutputLen = 16,
  kEdnBusAckMaxData = 64,
};

static dif_rv_core_ibex_t rv_core_ibex;
static dif_entropy_src_t entropy_src;
static dif_csrng_t csrng;
static dif_edn_t edn0;
static dif_edn_t edn1;

status_t handle_rng_fi_edn_bus_ack(ujson_t *uj) {
  // Clear registered alerts in alert handler.
  sca_registered_alerts_t reg_alerts = sca_get_triggered_alerts();
  // Enable entropy complex, CSRNG and EDN so Ibex can get entropy.
  // Configure entropy in auto_mode to avoid starving the system from entropy,
  // given that boot mode entropy has a limited number of generated bits.
  TRY(entropy_testutils_auto_mode_init());

  uint32_t ibex_rnd_data[kEdnBusAckMaxData];

  // Inject faults during generating and receiving random data.
  // Goal is to manipulate ACK on bus to trigger that the same
  // data chunk is transmitted multiple times.
  sca_set_trigger_high();
  asm volatile(NOP10);
  for (size_t it = 0; it < kEdnBusAckMaxData; it++) {
    TRY(rv_core_ibex_testutils_get_rnd_data(&rv_core_ibex, kEdnKatTimeout,
                                            &ibex_rnd_data[it]));
  }
  sca_set_trigger_low();

  // Check if there are any collisions.
  rng_fi_edn_ack_t uj_output;
  memset(uj_output.rand, 0, sizeof(uj_output.rand));
  size_t collisions = 0;
  for (size_t outer = 0; outer < kEdnBusAckMaxData; outer++) {
    for (size_t inner = 0; inner < kEdnBusAckMaxData; inner++) {
      if (outer != inner) {
        if (ibex_rnd_data[outer] == ibex_rnd_data[inner]) {
          collisions++;
          if (collisions < 16) {
            uj_output.rand[collisions] = ibex_rnd_data[outer];
          }
        }
      }
    }
  }

  // Get registered alerts from alert handler.
  reg_alerts = sca_get_triggered_alerts();

  // Read ERR_STATUS register from Ibex.
  dif_rv_core_ibex_error_status_t err_ibx;
  TRY(dif_rv_core_ibex_get_error_status(&rv_core_ibex, &err_ibx));

  // Send result & ERR_STATUS to host.
  uj_output.collisions = collisions;
  memcpy(uj_output.alerts, reg_alerts.alerts, sizeof(reg_alerts.alerts));
  uj_output.err_status = err_ibx;
  RESP_OK(ujson_serialize_rng_fi_edn_ack_t, uj, &uj_output);
  return OK_STATUS();
}

status_t handle_rng_fi_edn_init(ujson_t *uj) {
  sca_select_trigger_type(kScaTriggerTypeSw);
  // As we are using the software defined trigger, the first argument of
  // sca_init is not needed. kScaTriggerSourceAes is selected as a placeholder.
  sca_init(kScaTriggerSourceAes, kScaPeripheralIoDiv4 | kScaPeripheralEntropy |
                                     kScaPeripheralCsrng | kScaPeripheralEdn);

  // Disable the instruction cache and dummy instructions for FI attacks.
  sca_configure_cpu();

  // Configure Ibex to allow reading ERR_STATUS register.
  TRY(dif_rv_core_ibex_init(
      mmio_region_from_addr(TOP_EARLGREY_RV_CORE_IBEX_CFG_BASE_ADDR),
      &rv_core_ibex));

  // Configure the alert handler. Alerts triggered by IP blocks are captured
  // and reported to the test.
  sca_configure_alert_handler();

  // Initialize peripherals used in this FI test.
  TRY(dif_entropy_src_init(
      mmio_region_from_addr(TOP_EARLGREY_ENTROPY_SRC_BASE_ADDR), &entropy_src));
  TRY(dif_csrng_init(mmio_region_from_addr(TOP_EARLGREY_CSRNG_BASE_ADDR),
                     &csrng));
  TRY(dif_edn_init(mmio_region_from_addr(TOP_EARLGREY_EDN0_BASE_ADDR), &edn0));
  TRY(dif_edn_init(mmio_region_from_addr(TOP_EARLGREY_EDN1_BASE_ADDR), &edn1));

  // Read device ID and return to host.
  penetrationtest_device_id_t uj_output;
  TRY(sca_read_device_id(uj_output.device_id));
  RESP_OK(ujson_serialize_penetrationtest_device_id_t, uj, &uj_output);

  return OK_STATUS();
}

status_t handle_rng_fi_csrng_bias(ujson_t *uj) {
  // Get the test mode.
  crypto_fi_csrng_mode_t uj_data;
  TRY(ujson_deserialize_crypto_fi_csrng_mode_t(uj, &uj_data));
  // Clear registered alerts in alert handler.
  sca_registered_alerts_t reg_alerts = sca_get_triggered_alerts();

  TRY(csrng_testutils_cmd_ready_wait(&csrng));
  TRY(dif_csrng_uninstantiate(&csrng));

  const dif_csrng_seed_material_t kEntropyInput = {
      .seed_material = {0x73bec010, 0x9262474c, 0x16a30f76, 0x531b51de,
                        0x2ee494e5, 0xdfec9db3, 0xcb7a879d, 0x5600419c,
                        0xca79b0b0, 0xdda33b5c, 0xa468649e, 0xdf5d73fa},
      .seed_material_len = 12,
  };

  CHECK_DIF_OK(dif_csrng_instantiate(&csrng, kDifCsrngEntropySrcToggleDisable,
                                     &kEntropyInput));

  // FI code target.
  uint32_t rand_data_got[kCsrngExpectedOutputLen];
  TRY(csrng_testutils_cmd_ready_wait(&csrng));

  if (uj_data.all_trigger || uj_data.start_trigger) {
    sca_set_trigger_high();
  }
  TRY(dif_csrng_generate_start(&csrng, kCsrngExpectedOutputLen));
  if (uj_data.start_trigger) {
    sca_set_trigger_low();
  }

  if (uj_data.valid_trigger) {
    sca_set_trigger_high();
  }
  dif_csrng_output_status_t output_status;
  do {
    TRY(dif_csrng_get_output_status(&csrng, &output_status));
  } while (!output_status.valid_data);
  if (uj_data.valid_trigger) {
    sca_set_trigger_low();
  }

  if (uj_data.read_trigger) {
    sca_set_trigger_high();
  }
  TRY(dif_csrng_generate_read(&csrng, rand_data_got, kCsrngExpectedOutputLen));
  if (uj_data.all_trigger || uj_data.read_trigger) {
    sca_set_trigger_low();
  }

  // Get registered alerts from alert handler.
  reg_alerts = sca_get_triggered_alerts();

  // Read ERR_STATUS register from Ibex.
  dif_rv_core_ibex_error_status_t err_ibx;
  TRY(dif_rv_core_ibex_get_error_status(&rv_core_ibex, &err_ibx));

  // Compare with expected data.
  const uint32_t kExpectedOutput[kCsrngExpectedOutputLen] = {
      932170270, 3480632584, 387346064, 186012424, 899661374, 2795183089,
      336687633, 3222931513, 1490543709, 3319795384, 3464147855, 1850271046,
      1239323641, 2292604615, 3314177342, 1567494162,
  };
  rng_fi_csrng_output_t uj_output;
  uj_output.res = 0;
  for (size_t it = 0; it < kCsrngExpectedOutputLen; it++) {
    if (rand_data_got[it] != kExpectedOutput[it]) {
      uj_output.res = 1;
    }
  }

  // Send result & ERR_STATUS to host.
  memcpy(uj_output.rand, rand_data_got, sizeof(rand_data_got));
  uj_output.err_status = err_ibx;
  memcpy(uj_output.alerts, reg_alerts.alerts, sizeof(reg_alerts.alerts));
  RESP_OK(ujson_serialize_rng_fi_csrng_output_t, uj, &uj_output);

  return OK_STATUS();
}

status_t handle_rng_fi_csrng_init(ujson_t *uj) {
  sca_select_trigger_type(kScaTriggerTypeSw);
  // As we are using the software defined trigger, the first argument of
  // sca_init is not needed. kScaTriggerSourceAes is selected as a placeholder.
  sca_init(kScaTriggerSourceAes, kScaPeripheralIoDiv4 | kScaPeripheralCsrng);

  // Disable the instruction cache and dummy instructions for FI attacks.
  sca_configure_cpu();

  // Configure Ibex to allow reading ERR_STATUS register.
  TRY(dif_rv_core_ibex_init(
      mmio_region_from_addr(TOP_EARLGREY_RV_CORE_IBEX_CFG_BASE_ADDR),
      &rv_core_ibex));

  // Configure the alert handler. Alerts triggered by IP blocks are captured
  // and reported to the test.
  sca_configure_alert_handler();

  // Initialize CSRNG.
  mmio_region_t base_addr = mmio_region_from_addr(TOP_EARLGREY_CSRNG_BASE_ADDR);
  CHECK_DIF_OK(dif_csrng_init(base_addr, &csrng));
  CHECK_DIF_OK(dif_csrng_configure(&csrng));

  // Read device ID and return to host.
  penetrationtest_device_id_t uj_output;
  TRY(sca_read_device_id(uj_output.device_id));
  RESP_OK(ujson_serialize_penetrationtest_device_id_t, uj, &uj_output);

  return OK_STATUS();
}

status_t handle_rng_fi(ujson_t *uj) {
  rng_fi_subcommand_t cmd;
  TRY(ujson_deserialize_rng_fi_subcommand_t(uj, &cmd));
  switch (cmd) {
    case kRngFiSubcommandCsrngInit:
      return handle_rng_fi_csrng_init(uj);
    case kRngFiSubcommandCsrngBias:
      return handle_rng_fi_csrng_bias(uj);
    case kRngFiSubcommandEdnInit:
      return handle_rng_fi_edn_init(uj);
    case kRngFiSubcommandEdnBusAck:
      return handle_rng_fi_edn_bus_ack(uj);
    default:
      LOG_ERROR("Unrecognized RNG FI subcommand: %d", cmd);
      return INVALID_ARGUMENT();
  }
  return OK_STATUS();
}
