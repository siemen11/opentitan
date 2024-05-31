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
  kCsrngExpectedOutputLen = 16,
};

static dif_rv_core_ibex_t rv_core_ibex;
static dif_csrng_t csrng;

status_t handle_csrng_bias(ujson_t *uj) {
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
  sca_set_trigger_high();
  asm volatile(NOP30);
  TRY(csrng_testutils_cmd_generate_run(&csrng, rand_data_got,
                                       kCsrngExpectedOutputLen));
  asm volatile(NOP30);
  sca_set_trigger_low();

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
      return handle_csrng_bias(uj);
    default:
      LOG_ERROR("Unrecognized RNG FI subcommand: %d", cmd);
      return INVALID_ARGUMENT();
  }
  return OK_STATUS();
}
