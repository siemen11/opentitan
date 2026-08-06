// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/crypto/drivers/otbn.h"
#include "sw/device/lib/crypto/include/datatypes.h"
#include "sw/device/lib/crypto/include/integrity.h"
#include "sw/device/lib/crypto/include/mldsa.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

OTTF_DEFINE_TEST_CONFIG();

static const uint8_t kMessage[] = "Hello world";

// Initial prefix of signature from Wycheproof test #66.
static const uint8_t kSigPrefix[65] = {
    130, 103, 86,  202, 236, 108, 144, 12,  113, 9,   10,  163, 192, 97,  30,  65,
    121, 35,  235, 180, 157, 90,  137, 20,  240, 107, 151, 13,  229, 105, 247, 119,
    116, 213, 137, 171, 97,  118, 223, 234, 166, 47,  10,  202, 124, 131, 100, 44,
    121, 117, 134, 204, 76,  57,  29,  207, 121, 249, 160, 244, 90,  143, 110, 242,
    0};

// Pattern bytes for the rest of signature in test #66: 0, 8, 0, 128 repeat.
static const uint8_t kSigPattern[4] = {0, 8, 0, 128};

static uint8_t pk_buf[2592];
static uint32_t sig_words[1157];

bool test_main(void) {
  LOG_INFO("Starting ML-DSA-87 test #66 verification functest...");

  // Build public key: 32 bytes of 42, followed by 2560 zeroes.
  memset(pk_buf, 0, sizeof(pk_buf));
  memset(pk_buf, 42, 32);

  otcrypto_unblinded_key_t pk = {
      .key_mode = kOtcryptoKeyModePqcMldsa87,
      .key_length = sizeof(pk_buf),
      .key = (uint32_t *)pk_buf,
  };
  pk.checksum = otcrypto_integrity_unblinded_checksum(&pk);

  otcrypto_const_byte_buf_t msg =
      otcrypto_make_const_byte_buf(kMessage, sizeof(kMessage) - 1);
  otcrypto_const_byte_buf_t ctx =
      otcrypto_make_const_byte_buf(NULL, 0);

  // Build signature buffer (4627 bytes in word buffer).
  uint8_t *sig_bytes = (uint8_t *)sig_words;
  memset(sig_words, 0, sizeof(sig_words));
  memcpy(sig_bytes, kSigPrefix, sizeof(kSigPrefix));
  for (size_t i = sizeof(kSigPrefix); i < 4627; ++i) {
    sig_bytes[i] = kSigPattern[(i - sizeof(kSigPrefix)) % 4];
  }

  otcrypto_const_word32_buf_t sig =
      otcrypto_make_const_word32_buf(sig_words, 1157);

  hardened_bool_t verification_result = kHardenedBoolFalse;

  LOG_INFO("Calling otcrypto_mldsa87_verify...");
  otcrypto_status_t status = otcrypto_mldsa87_verify(
      &pk, &msg, &ctx, &sig, kOtcryptoMldsaHashModePure, &verification_result);

  LOG_INFO("otcrypto_mldsa87_verify returned status = 0x%x, valid = %d",
           status.value, verification_result == kHardenedBoolTrue);

  CHECK(status.value == kOtcryptoStatusValueOk,
        "otcrypto_mldsa87_verify failed with status 0x%x", status.value);
  CHECK(verification_result == kHardenedBoolFalse,
        "Expected verification_result == false for test #66");

  return true;
}
