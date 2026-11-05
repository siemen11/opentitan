// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/math.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/crypto/impl/status.h"
#include "sw/device/lib/crypto/include/config.h"
#include "sw/device/lib/crypto/include/cryptolib_build_info.h"
#include "sw/device/lib/crypto/include/datatypes.h"
#include "sw/device/lib/crypto/include/integrity.h"
#include "sw/device/lib/crypto/include/rsa.h"
#include "sw/device/lib/crypto/include/sha1.h"
#include "sw/device/lib/crypto/include/sha2.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

// Module ID for status codes.
#define MODULE_ID MAKE_MODULE_ID('t', 's', 't')

/**
 * Android KeyMint VTS (`SigningOperationsTest.Rsa*` &
 * `EncryptionOperationsTest.Rsa*`) conformance test suite for `otcrypto_rsa`.
 *
 * Upstream AOSP References:
 *   -
 * `hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintTest.cpp`
 *     (Signing lines 2935-3415; Encryption lines 5410-5834)
 *   - `cts/tests/tests/keystore/src/android/keystore/cts/CipherTest.java`
 *   - `cts/tests/tests/keystore/src/android/keystore/cts/SignatureTest.java`
 *
 * Test Mapping:
 *   - `rsa_vts_signing_no_digest_and_raw_test`:
 *     - `TEST_P(SigningOperationsTest, RsaSuccess)` (L2935)
 *     - `TEST_P(SigningOperationsTest, RsaPkcs1NoDigestSuccess)` (L3122)
 *     - `TEST_P(SigningOperationsTest, RsaPkcs1NoDigestTooLong)` (L3141)
 *     - `TEST_P(SigningOperationsTest, RsaNoDigest)` (L3321)
 *     - `TEST_P(SigningOperationsTest, RsaTooShortMessage)` (L3359)
 *     - `TEST_P(SigningOperationsTest, RsaSignTooLargeMessage)` (L3399)
 *   - `rsa_vts_signing_pkcs1_and_pss_hashes_test`:
 *     - `TEST_P(SigningOperationsTest, RsaAllPaddingsAndDigests)` (L2954)
 *     - `TEST_P(SigningOperationsTest, RsaPssSha256Success)` (L3039)
 *     - `TEST_P(SigningOperationsTest, RsaPkcs1Sha256Success)` (L3104)
 *   - `rsa_vts_encryption_modes_test`:
 *     - `TEST_P(EncryptionOperationsTest, RsaNoPaddingSuccess)` (L5410)
 *     - `TEST_P(EncryptionOperationsTest, RsaNoPaddingShortMessage)` (L5439)
 *     - `TEST_P(EncryptionOperationsTest, RsaOaepSuccess)` (L5463)
 *     - `TEST_P(EncryptionOperationsTest, RsaOaepInvalidDigest)` (L5525)
 *     - `TEST_P(EncryptionOperationsTest, RsaOaepDecryptWithWrongDigest)`
 * (L5561)
 *     - `TEST_P(EncryptionOperationsTest, RsaPkcs1Success)` (L5801)
 *     - `CipherTest.java:956` (`testMaxSizedPlaintextSupported`) & `1036`
 *       (`testLargerThanMaxSizedPlaintextRejected`)
 *   - `rsa_vts_cts_empty_plaintext_and_no_digest_test`:
 *     - `CipherTest.java:398` (`testEmptyPlaintextEncryptsAndDecrypts`)
 *     - `TEST_P(EncryptionOperationsTest, RsaPkcs1Success)` (L5801)
 *     - `TEST_P(SigningOperationsTest, RsaNoDigest)` (L3321, 0-byte message)
 */

enum {
  kRsa2048NumBytes = 2048 / 8,
  kRsa2048NumWords = kRsa2048NumBytes / sizeof(uint32_t),
  kMaxPkcs1v15PayloadBytes = kRsa2048NumBytes - 11,
};

// Test RSA-2048 key pair (e = 65537).
static const uint32_t kTestModulus[kRsa2048NumWords] = {
    0x40d984b1, 0x3611356d, 0x9eb2f35c, 0x031a892c, 0x16354662, 0x6a260bad,
    0xb2b807d6, 0xb7de7ccb, 0x278492e0, 0x41adab06, 0x9e60110f, 0x1414eeff,
    0x8b80e14e, 0x5eb5ae79, 0x0d98fa5b, 0x58bece1f, 0xcf6bdca8, 0x82f5611f,
    0x351e3869, 0x075005d6, 0xe813fe23, 0xdd967a37, 0x682d1c41, 0x9fdd2d8c,
    0x21bdd5fc, 0x4fc459c7, 0x508c9293, 0x1f9ac759, 0x55aacb04, 0x58389f05,
    0x0d0b00fb, 0x59bb4141, 0x68f9e0bf, 0xc2f1a546, 0x0a71ad19, 0x9c400301,
    0xa4f8ecb9, 0xcdf39538, 0xaabe9cb0, 0xd9f7b2dc, 0x0e8b292d, 0x8ef6c717,
    0x720e9520, 0xb0c6a23e, 0xda1e92b1, 0x8b6b4800, 0x2f25082b, 0x7f2d6711,
    0x426fc94f, 0x9926ba5a, 0x89bd4d2b, 0x977718d5, 0x5a8406be, 0x87d090f3,
    0x639f9975, 0x5948488b, 0x1d3d9cd7, 0x28c7956b, 0xebb97a3e, 0x1edbf4e2,
    0x105cc797, 0x924ec514, 0x146810df, 0xb1ab4a49,
};

static const uint32_t kTestPrivateExponent[kRsa2048NumWords] = {
    0x0b19915b, 0xa6a935e6, 0x426b2e10, 0xb4ff0629, 0x7322343b, 0x3f28c8d5,
    0x190757ce, 0x87409d6b, 0xd88e282b, 0x01c13c2a, 0xebb79189, 0x74cbeab9,
    0x93de5d54, 0xae1bc80a, 0x083a75f2, 0xd574d229, 0xeb46696e, 0x7648cfb6,
    0xe7ad1b36, 0xbd0e81b2, 0x19c72703, 0xebea5085, 0xf8c7d152, 0x34dcf84d,
    0xa437187f, 0x41e4f88e, 0xe4e35f9f, 0xcd8bc6f8, 0x7f98e2f2, 0xffdf75ca,
    0x3698226e, 0x903f2a56, 0xbf21a6dc, 0x97cbf653, 0xe9d80cb3, 0x55dc1685,
    0xe0ebae21, 0xc8171e18, 0x8e73d26d, 0xbbdbaac1, 0x886e8007, 0x673c9da4,
    0xe2cb0698, 0xa9f1ba2d, 0xedab4f0a, 0x197e890c, 0x65e7e736, 0x1de28f24,
    0x57cf5137, 0x631ff441, 0x22539942, 0xcee3fd41, 0xd22b5f8a, 0x995dd87a,
    0xcaa6815c, 0x08ca0fd3, 0x8f996093, 0x30b7c446, 0xf69b11f7, 0xa298dd00,
    0xfd4e8120, 0x059df602, 0x25feb268, 0x0f3f749e,
};

static const uint8_t kTestMessage[] = "KeyMint VTS/CTS RSA test message.";
static const size_t kTestMessageLen = sizeof(kTestMessage) - 1;

static const uint8_t kTestLabel[] = "KeyMint OAEP label";
static const size_t kTestLabelLen = sizeof(kTestLabel) - 1;

/**
 * Helper to construct RSA-2048 public and private keys for a given key mode.
 */
static status_t construct_rsa2048_keypair(otcrypto_key_mode_t key_mode,
                                          uint32_t *pub_key_data,
                                          otcrypto_unblinded_key_t *public_key,
                                          uint32_t *priv_keyblob,
                                          otcrypto_blinded_key_t *private_key) {
  otcrypto_const_word32_buf_t modulus = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kTestModulus, ARRAYSIZE(kTestModulus));
  otcrypto_const_word32_buf_t d_share0 =
      OTCRYPTO_MAKE_BUF(otcrypto_const_word32_buf_t, kTestPrivateExponent,
                        ARRAYSIZE(kTestPrivateExponent));
  uint32_t share1[kRsa2048NumWords] = {0};
  otcrypto_const_word32_buf_t d_share1 =
      OTCRYPTO_MAKE_BUF(otcrypto_const_word32_buf_t, share1, ARRAYSIZE(share1));

  *public_key = (otcrypto_unblinded_key_t){
      .key_mode = key_mode,
      .key_length = kOtcryptoRsa2048PublicKeyBytes,
      .key = pub_key_data,
  };
  TRY(otcrypto_rsa_public_key_construct(kOtcryptoRsaSize2048, &modulus,
                                        public_key));

  *private_key = (otcrypto_blinded_key_t){
      .config =
          {
              .version = otcrypto_lib_version(),
              .key_mode = key_mode,
              .key_length = kOtcryptoRsa2048PrivateKeyBytes,
              .hw_backed = kHardenedBoolFalse,
              .security_level = kOtcryptoKeySecurityLevelLow,
          },
      .keyblob = priv_keyblob,
      .keyblob_length = kOtcryptoRsa2048PrivateKeyblobBytes,
  };
  TRY(otcrypto_rsa_private_key_from_exponents(
      kOtcryptoRsaSize2048, &modulus, &d_share0, &d_share1, private_key));
  return OK_STATUS();
}

/**
 * Source:
 *   - `KeyMintTest.cpp:2935` — `TEST_P(SigningOperationsTest, RsaSuccess)`
 *   - `KeyMintTest.cpp:3122` —
 *     `TEST_P(SigningOperationsTest, RsaPkcs1NoDigestSuccess)`
 *   - `KeyMintTest.cpp:3141` —
 *     `TEST_P(SigningOperationsTest, RsaPkcs1NoDigestTooLong)`
 *   - `KeyMintTest.cpp:3321` — `TEST_P(SigningOperationsTest, RsaNoDigest)`
 *   - `KeyMintTest.cpp:3359` —
 *     `TEST_P(SigningOperationsTest, RsaTooShortMessage)`
 *   - `KeyMintTest.cpp:3399` —
 *     `TEST_P(SigningOperationsTest, RsaSignTooLargeMessage)`
 */
static status_t rsa_vts_signing_no_digest_and_raw_test(void) {
  LOG_INFO("Testing SigningOperationsTest.RsaNoDigest (PKCS#1 v1.5 & Raw)");
  uint32_t pub_data[ceil_div(kOtcryptoRsa2048PublicKeyBytes, sizeof(uint32_t))];
  uint32_t priv_blob[ceil_div(kOtcryptoRsa2048PrivateKeyblobBytes,
                              sizeof(uint32_t))];
  otcrypto_unblinded_key_t public_key;
  otcrypto_blinded_key_t private_key;

  // 1. PKCS#1 v1.5 Sign/Verify with `kOtcryptoHashModeNull` (unhashed raw
  // message up to k - 11 = 245 bytes; Note: otcrypto_hash_digest_t.len is in
  // 32-bit words, so word-aligned lengths up to 244 bytes are supported).
  TRY(construct_rsa2048_keypair(kOtcryptoKeyModeRsaSignPkcs, pub_data,
                                &public_key, priv_blob, &private_key));

  uint32_t raw_digest_words[61];  // 244 bytes (max word-aligned <= 245 bytes)
  for (size_t i = 0; i < ARRAYSIZE(raw_digest_words); ++i) {
    raw_digest_words[i] = 0x10203040u + (uint32_t)i;
  }
  otcrypto_hash_digest_t null_digest = {
      .mode = kOtcryptoHashModeNull,
      .data = raw_digest_words,
      .len = ARRAYSIZE(raw_digest_words),
  };

  uint32_t sig[kRsa2048NumWords];
  otcrypto_word32_buf_t sig_buf =
      OTCRYPTO_MAKE_BUF(otcrypto_word32_buf_t, sig, ARRAYSIZE(sig));
  otcrypto_const_word32_buf_t const_sig_buf =
      OTCRYPTO_MAKE_BUF(otcrypto_const_word32_buf_t, sig, ARRAYSIZE(sig));

  TRY(otcrypto_rsa_sign(&private_key, null_digest, kOtcryptoRsaPaddingPkcs,
                        &sig_buf));
  hardened_bool_t verif_ok = kHardenedBoolFalse;
  TRY(otcrypto_rsa_verify(&public_key, null_digest, kOtcryptoRsaPaddingPkcs,
                          &const_sig_buf, &verif_ok));
  TRY_CHECK(verif_ok == kHardenedBoolTrue);

  // Tamper with the unhashed message and verify PKCS#1 v1.5 verification fails.
  raw_digest_words[0] ^= 1u;
  TRY(otcrypto_rsa_verify(&public_key, null_digest, kOtcryptoRsaPaddingPkcs,
                          &const_sig_buf, &verif_ok));
  TRY_CHECK(verif_ok == kHardenedBoolFalse);
  raw_digest_words[0] ^= 1u;

  // PKCS#1 v1.5 with `kOtcryptoHashModeNull` must reject payloads > 245 bytes
  // (e.g., 62 words = 248 bytes).
  uint32_t too_long_digest_words[62] = {0};
  otcrypto_hash_digest_t too_long_digest = {
      .mode = kOtcryptoHashModeNull,
      .data = too_long_digest_words,
      .len = ARRAYSIZE(too_long_digest_words),
  };
  TRY_CHECK(otcrypto_rsa_sign(&private_key, too_long_digest,
                              kOtcryptoRsaPaddingPkcs, &sig_buf)
                .value == OTCRYPTO_BAD_ARGS.value);

  // 2. Raw RSA (`PaddingMode::NONE` + `Digest::NONE`):
  // KeyMint left-pads short messages with zero bytes (big-endian) = right-pads
  // with zero words in little-endian representation.
  TRY(construct_rsa2048_keypair(kOtcryptoKeyModeRsaRaw, pub_data, &public_key,
                                priv_blob, &private_key));
  uint32_t raw_block[kRsa2048NumWords] = {0};
  memcpy(raw_block, kTestMessage, kTestMessageLen);
  otcrypto_hash_digest_t raw_block_digest = {
      .mode = kOtcryptoHashModeNull,
      .data = raw_block,
      .len = ARRAYSIZE(raw_block),
  };
  TRY(otcrypto_rsa_sign(&private_key, raw_block_digest, kOtcryptoRsaPaddingNull,
                        &sig_buf));
  verif_ok = kHardenedBoolFalse;
  TRY(otcrypto_rsa_verify(&public_key, raw_block_digest,
                          kOtcryptoRsaPaddingNull, &const_sig_buf, &verif_ok));
  TRY_CHECK(verif_ok == kHardenedBoolTrue);

  // Raw RSA must reject input numerically >= modulus.
  uint32_t ge_modulus[kRsa2048NumWords];
  memcpy(ge_modulus, kTestModulus, sizeof(ge_modulus));
  otcrypto_hash_digest_t ge_mod_digest = {
      .mode = kOtcryptoHashModeNull,
      .data = ge_modulus,
      .len = ARRAYSIZE(ge_modulus),
  };
  TRY_CHECK(otcrypto_rsa_sign(&private_key, ge_mod_digest,
                              kOtcryptoRsaPaddingNull, &sig_buf)
                .value == OTCRYPTO_BAD_ARGS.value);

  // KeyMintTest.cpp:3321 (`SigningOperationsTest.RsaNoDigest`):
  // RSA-PSS (`kOtcryptoRsaPaddingPss`) with `Digest::NONE`
  // (`kOtcryptoHashModeNull`) must fail with `OTCRYPTO_BAD_ARGS`.
  TRY(construct_rsa2048_keypair(kOtcryptoKeyModeRsaSignPss, pub_data,
                                &public_key, priv_blob, &private_key));
  TRY_CHECK(otcrypto_rsa_sign(&private_key, null_digest, kOtcryptoRsaPaddingPss,
                              &sig_buf)
                .value == OTCRYPTO_BAD_ARGS.value);

  return OK_STATUS();
}

/**
 * SigningOperationsTest.RsaAllPaddingsAndDigests, RsaPkcs1Sha256Success, &
 * RsaPssSha256Success (`KeyMintTest.cpp:2954-3115`).
 *
 * Tests both PKCS#1 v1.5 and PSS across SHA-1, SHA-256, SHA-384, and SHA-512,
 * plus corrupted signature rejection (`++corrupt[64]`).
 */
static status_t rsa_vts_signing_pkcs1_and_pss_hashes_test(void) {
  LOG_INFO(
      "Testing SigningOperationsTest.RsaAllPaddingsAndDigests "
      "(PKCS#1 v1.5 & PSS across SHA-1/256/384/512)");
  uint32_t pub_data[ceil_div(kOtcryptoRsa2048PublicKeyBytes, sizeof(uint32_t))];
  uint32_t priv_blob[ceil_div(kOtcryptoRsa2048PrivateKeyblobBytes,
                              sizeof(uint32_t))];
  otcrypto_unblinded_key_t public_key;
  otcrypto_blinded_key_t private_key;

  otcrypto_const_byte_buf_t msg_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_const_byte_buf_t, kTestMessage, kTestMessageLen);
  uint32_t sha1_words[160 / 32];
  otcrypto_hash_digest_t sha1_digest = {
      .mode = kOtcryptoHashModeSha1,
      .data = sha1_words,
      .len = ARRAYSIZE(sha1_words),
  };
  TRY(otcrypto_sha1(&msg_buf, &sha1_digest));

  uint32_t sha256_words[256 / 32];
  otcrypto_hash_digest_t sha256_digest = {
      .mode = kOtcryptoHashModeSha256,
      .data = sha256_words,
      .len = ARRAYSIZE(sha256_words),
  };
  TRY(otcrypto_sha2_256(&msg_buf, &sha256_digest));

  uint32_t sha384_words[384 / 32];
  otcrypto_hash_digest_t sha384_digest = {
      .mode = kOtcryptoHashModeSha384,
      .data = sha384_words,
      .len = ARRAYSIZE(sha384_words),
  };
  TRY(otcrypto_sha2_384(&msg_buf, &sha384_digest));

  uint32_t sha512_words[512 / 32];
  otcrypto_hash_digest_t sha512_digest = {
      .mode = kOtcryptoHashModeSha512,
      .data = sha512_words,
      .len = ARRAYSIZE(sha512_words),
  };
  TRY(otcrypto_sha2_512(&msg_buf, &sha512_digest));

  const otcrypto_hash_digest_t kDigests[4] = {sha1_digest, sha256_digest,
                                              sha384_digest, sha512_digest};
  const otcrypto_rsa_padding_t kPaddings[2] = {kOtcryptoRsaPaddingPkcs,
                                               kOtcryptoRsaPaddingPss};
  const otcrypto_key_mode_t kKeyModes[2] = {kOtcryptoKeyModeRsaSignPkcs,
                                            kOtcryptoKeyModeRsaSignPss};

  for (size_t p = 0; p < ARRAYSIZE(kPaddings); ++p) {
    TRY(construct_rsa2048_keypair(kKeyModes[p], pub_data, &public_key,
                                  priv_blob, &private_key));
    for (size_t d = 0; d < ARRAYSIZE(kDigests); ++d) {
      uint32_t sig[kRsa2048NumWords];
      otcrypto_word32_buf_t sig_buf =
          OTCRYPTO_MAKE_BUF(otcrypto_word32_buf_t, sig, ARRAYSIZE(sig));
      otcrypto_const_word32_buf_t const_sig_buf =
          OTCRYPTO_MAKE_BUF(otcrypto_const_word32_buf_t, sig, ARRAYSIZE(sig));

      TRY(otcrypto_rsa_sign(&private_key, kDigests[d], kPaddings[p], &sig_buf));
      hardened_bool_t verif_ok = kHardenedBoolFalse;
      TRY(otcrypto_rsa_verify(&public_key, kDigests[d], kPaddings[p],
                              &const_sig_buf, &verif_ok));
      TRY_CHECK(verif_ok == kHardenedBoolTrue);

      // KeyMintTest.cpp:2998: Corrupt middle word of signature and verify
      // verification fails (`verif_ok == kHardenedBoolFalse`).
      sig[kRsa2048NumWords / 2] ^= 1u;
      verif_ok = kHardenedBoolTrue;
      TRY(otcrypto_rsa_verify(&public_key, kDigests[d], kPaddings[p],
                              &const_sig_buf, &verif_ok));
      TRY_CHECK(verif_ok == kHardenedBoolFalse);
    }
  }

  // Android CTS `SignatureTest.java:132-230` (`SHORT_MSG_KAT_SIGNATURES` /
  // `testSmallMsgKat`): Verify all 9 RSA-2048 KAT signatures (`NONEwithRSA`,
  // `SHA{1,256,384,512}withRSA`, and `SHA{1,256,384,512}withRSA/PSS`) using
  // `R.raw.rsa_key1_pkcs8` over the 23-byte message
  // `ec174729c4f5c570ba0de4c424cdcbf0362a7718039464`.
  static const uint32_t kCtsRsaKey1Modulus[kRsa2048NumWords] = {
      0xd92e0d1b, 0xce2f1e85, 0xbb6873fe, 0xba242e6b, 0x063bc171, 0x5588891e,
      0x026b82e3, 0x662b3af7, 0x6861b531, 0x7f32a064, 0xa4f2e40f, 0x525d08a9,
      0x3e1e3f90, 0xf8a04bad, 0x800e2e7e, 0xa6802e08, 0x97335cc0, 0xac1105db,
      0x0748f766, 0x91445f81, 0xd8a1c606, 0x8af766bb, 0xf0e62491, 0xbc94abb2,
      0x822c75b4, 0xd5847d32, 0x865067e2, 0xfc5cf901, 0xe3cf871b, 0x27712a16,
      0x84d28d74, 0x628fc019, 0x95807a5d, 0x4b1e4d00, 0xb381b33c, 0xf8535b34,
      0xfdea7d47, 0x86ae9d71, 0xfb849c8c, 0xed30dfa8, 0xc9d21df3, 0xb722e302,
      0xdb0e2856, 0x7c7e80dd, 0x27e90213, 0x0e06036a, 0xe56195f4, 0xd11996bb,
      0x9813efd4, 0x477a1a7e, 0x792e2bf3, 0xca5c8516, 0x1d028c69, 0xad38e7a3,
      0xd09131f4, 0xecf87648, 0xa42ebb5d, 0xa5288112, 0xdb2d7a82, 0x4b2c7fdf,
      0x05ce7552, 0xcd8f4358, 0x194eb182, 0xa0f855d8,
  };
  static const uint32_t kCtsRsaKey1PrivExp[kRsa2048NumWords] = {
      0xa6969321, 0xd405ec7b, 0x10214571, 0x0628ad1b, 0x200ca6e4, 0x02be5a90,
      0xdf7ab15a, 0x00028eca, 0x934138b0, 0xabf4d82a, 0x6825c2c3, 0xd060bbed,
      0x8bad093e, 0x50bd2e36, 0x2d92880f, 0x573919cd, 0x069753c9, 0xe5502044,
      0x0975544d, 0x9e7cafd0, 0xeeec95e2, 0x64260aa7, 0x312fb96c, 0xd2740049,
      0xd94b1803, 0x46f5a373, 0x223d2527, 0xf2b82abc, 0x6b51cee6, 0x1cc0713c,
      0x8c24c504, 0x27bcdc78, 0x4e5e6537, 0xcff08bb0, 0x3a2496d4, 0x0a8f00cc,
      0x0e166e91, 0xdfa180e9, 0xf5d61c52, 0x8965e5ee, 0x2340db06, 0x663b8ccc,
      0xad1f2bfc, 0x93291db8, 0x977f004c, 0x6116e1f7, 0x6953eac0, 0x06c41c97,
      0x84f536de, 0xa3edb422, 0x4983a3ec, 0xe3728aab, 0xffca6b7f, 0x6871f63c,
      0x9ff8ffbb, 0x8d64e712, 0x3394c017, 0xdb3619e4, 0xf363de41, 0x2750ca7f,
      0xe7497abc, 0xe93cf82c, 0x643a07e3, 0x9a076765,
  };
  static const uint32_t kCtsRsaNoneSig[kRsa2048NumWords] = {
      0x78d70eb0, 0x1f5ab6d5, 0xce717263, 0x41fbc17e, 0xa0debccb, 0x3b968635,
      0x98942d23, 0x0c78b4dc, 0x6e70c768, 0x86a00123, 0x3537680c, 0x8728455e,
      0x8867de05, 0x302f0fd2, 0xc95ea69f, 0x4de77831, 0x9252f4f7, 0x68155367,
      0x032add52, 0x53bf45e7, 0x9475f9be, 0x4dd7cbfa, 0x917e78ae, 0x6bc9fb30,
      0x8ecd6042, 0xb8b63eb9, 0xb45e1dd1, 0xc7c77e50, 0x79d66d38, 0x0224d2ee,
      0x417a8963, 0xbdea1dee, 0xe917680b, 0xa34b890c, 0xe1146aa2, 0xb566ca53,
      0xad96d04b, 0x868b3f8c, 0x353192c3, 0x40799cc0, 0xd8437958, 0xc0d8cc4c,
      0x0df3b5d9, 0x91919eff, 0xf913e1c8, 0x304c9b27, 0x7df0d4c5, 0xe9279958,
      0xcd1036d9, 0x08eb05d0, 0xeeab40b9, 0x29e5daf9, 0x16083ac9, 0x39f56ae6,
      0x0e78e00d, 0x580fee34, 0x88015d14, 0x63a53067, 0xa83b5d64, 0x7d7738e6,
      0x6adb2d5a, 0x9a5c4557, 0xe514ead2, 0x257d0704,
  };
  static const uint32_t kCtsRsaPkcs1Sha1Sig[kRsa2048NumWords] = {
      0xf905d6ff, 0x766fecc3, 0xa046ce8a, 0xe66efbdd, 0xbc0b6b87, 0x59d2ac3e,
      0x14e79581, 0xf91c0c2c, 0xd1d8f3dc, 0x3f96ba43, 0xdfb64642, 0x354a2040,
      0xca5c2f33, 0x4def2ba3, 0xcb18d65b, 0xdf9e466c, 0xb136c9ea, 0x79506e0e,
      0xa37f9bf0, 0xad4f97eb, 0x4556328b, 0x5ecaa5fc, 0xb07ab04b, 0x050054ce,
      0x17d3ae77, 0x8252736f, 0xf49ef364, 0xe07510c4, 0x00885325, 0x1b08e647,
      0x914b6c41, 0xcfe1c4ac, 0xea91d333, 0x17b34125, 0xfefe712d, 0x4f67a625,
      0x4c3e4a43, 0xf31e26e8, 0x2e600a38, 0x6e5cf73c, 0x1792985e, 0xc2cbfe15,
      0xdd3cbb6c, 0x2bf11c78, 0xb1cf31d4, 0x41c2b594, 0x4f2924e0, 0x05355aa8,
      0x8fa642ea, 0x8be98ccd, 0xa15619d7, 0xbc62180f, 0x8b4bc10a, 0x76a80e81,
      0x4a43fa3b, 0xfca85be1, 0xd4d0626a, 0xff1cd1e8, 0x8018ce52, 0x5d81dd51,
      0x9b90174f, 0x7d3e452c, 0xee18cbe2, 0x280977b4,
  };
  static const uint32_t kCtsRsaPkcs1Sha256Sig[kRsa2048NumWords] = {
      0x9da99745, 0x41fa129c, 0x6bb104ee, 0x55099bdb, 0x2c7b5ec8, 0xae6a67df,
      0x64dc2065, 0x6b472fd7, 0x622919cf, 0x1fee9d2e, 0x91bd6456, 0x0264b27d,
      0xb5309238, 0x68691adf, 0xc2ec999b, 0x00ce3899, 0x69ae6980, 0xfc81636e,
      0x512dbdc4, 0x8e8887ff, 0x1be51e0f, 0xc8a0ee6a, 0xff443948, 0x967fb7ec,
      0xf9664540, 0x4df4225c, 0xe28f4189, 0x7e1de2b8, 0xfc6f70fa, 0x4a29369f,
      0x095987af, 0x865b2d01, 0x36029820, 0x3e76c10d, 0xccc9a9ec, 0xe30a9dd6,
      0xa8e10ca2, 0x053ef0db, 0x536d61c8, 0x028ad906, 0xddef264d, 0xf640b589,
      0x054ad8f4, 0xc9407106, 0xc7c32810, 0x65b578bb, 0xdec5f015, 0x4b01112a,
      0x574df545, 0x1022fcd3, 0x89965045, 0x729ccc23, 0x4e10b1ba, 0x8f2040c8,
      0x4f3aff82, 0x55e30c8d, 0xaa73eb01, 0x921291c5, 0xc71c692e, 0x7853fbc9,
      0xb6e99a57, 0x777c932d, 0xedbf4c50, 0x1f1adcd6,
  };
  static const uint32_t kCtsRsaPkcs1Sha384Sig[kRsa2048NumWords] = {
      0xc80cb470, 0x4ef9ab00, 0x7a9189fe, 0x8f013c4c, 0x2b1283cd, 0xc0509e44,
      0x1ceac38e, 0xf8d084bf, 0xb07a53d7, 0x38a76f9d, 0xcea3eaf3, 0x67292c7f,
      0x0f423b37, 0x97c9bdc4, 0x202c1af9, 0xe52a205f, 0xa3ae09f7, 0x9f35483b,
      0x47c92a29, 0x8eaadd6d, 0x87f69906, 0xb047c33e, 0x552da2db, 0xafa8f940,
      0x79336efd, 0x2ca498b3, 0x7cd10c33, 0xb06f6f15, 0xdbbb530f, 0x13d736f7,
      0x5e8545fb, 0x493c6658, 0xebd501d8, 0xf12f2098, 0x738e95bd, 0x16731859,
      0xd612b1fc, 0xb85eef75, 0x1e9c4d27, 0x44d0ea15, 0x7c1cdeea, 0x467e8349,
      0x576f58b3, 0x875f0c97, 0xee2fef5b, 0x16ed218e, 0x903f8474, 0x3527fa45,
      0x37fac16a, 0x2a5c815f, 0xa90c3f3b, 0xe5aee0c8, 0x29b6414b, 0xe32db135,
      0x666d96b2, 0x29273097, 0x07cd9bac, 0x31d5071c, 0xbd31f7b5, 0x9c9f1d69,
      0x25524970, 0x642fa8c3, 0x62803569, 0x3b5e8baa,
  };
  static const uint32_t kCtsRsaPkcs1Sha512Sig[kRsa2048NumWords] = {
      0xc2f882f9, 0x355b437e, 0x9f5df78e, 0x843e62b4, 0x8868d795, 0xe3e90ea1,
      0x587230f7, 0x6cbc2a29, 0x64a43f0f, 0x3c989aeb, 0x3c1d88f9, 0x366877f5,
      0xbc2e399b, 0x6131de37, 0x556a9666, 0xab18d8e7, 0x478ebf91, 0x26899562,
      0xd3a17142, 0x953458f7, 0x41a756bc, 0x947d51a4, 0x6185f66d, 0xce87885c,
      0x01f5171a, 0xb7ae7d1f, 0xd98c0e3e, 0x20b18c54, 0x64200719, 0x35ff4be7,
      0x6e272037, 0x684485cd, 0x4545c3f6, 0x6f9e4cdd, 0xc280430e, 0x0c0a9450,
      0x03801833, 0x7760724c, 0x0db7d951, 0xba184e89, 0xfe0ea51d, 0x17c52f61,
      0xc5530375, 0x8aa0c45c, 0xe0a8389c, 0x6a84e607, 0x29122438, 0x9b92bf40,
      0x07a29315, 0x2594c7cb, 0x4a86b101, 0x6216ef7c, 0x5514130d, 0xe88fe3cf,
      0x8b0e02c3, 0x0857857c, 0xbbc81f80, 0x33413f30, 0xe900db23, 0xabe08203,
      0x26f79f64, 0x10780c2a, 0xd2ffefed, 0x23eb7577,
  };
  static const uint32_t kCtsRsaPssSha1Sig[kRsa2048NumWords] = {
      0x0c2d0834, 0xe392c9a6, 0xc8391473, 0x45529aa9, 0xc0becc3e, 0x2f76f0dd,
      0x005a7c76, 0xd97369ae, 0x08ec6351, 0xcaf6c653, 0x484f6f29, 0xce08adb6,
      0x3adf5248, 0x40ce615e, 0x47e4ca06, 0xa726ba88, 0xe8509e8b, 0xb5184b48,
      0x8a3a84bd, 0xb6439188, 0x61150dc1, 0x134ccc8b, 0xa34ac8d3, 0x2c4af832,
      0xa35a2b3a, 0xb88734cc, 0xda80799c, 0x657a1641, 0x2ec96a6b, 0xb2e49c7c,
      0x385a8340, 0xf7cd2db1, 0xa27ff84a, 0x12b4fac3, 0x9107e679, 0x76e29143,
      0xab922960, 0xf2bb6e3e, 0x595fbf44, 0xcbbb924d, 0x58be7407, 0xd31dbcce,
      0xda86276e, 0xabd1eb1a, 0xc21054b0, 0xc3ea595b, 0x7a0fada3, 0x57f6782b,
      0x24bbbad6, 0x21dde04d, 0xe3ebcd22, 0xd4c4d7d8, 0x4e5419f1, 0x76654201,
      0x5d3da39e, 0x14d2cffe, 0xd058025b, 0x1938c28c, 0x2038460e, 0x54af3603,
      0x04429a87, 0x25bc7cb2, 0x1695067a, 0x17e48378,
  };
  static const uint32_t kCtsRsaPssSha256Sig[kRsa2048NumWords] = {
      0xdc164c52, 0xf90c1fd6, 0xb87600a2, 0x16fbb9e9, 0x83b9149e, 0x22907e8b,
      0x32ad128f, 0x29151d86, 0x46dcff7b, 0x8b27c1b9, 0xd5617bae, 0x11eba649,
      0x1e408e80, 0xa8aca97d, 0xb76d4ed5, 0xfb895c6c, 0x4653e124, 0x617cdf57,
      0x00f7a4f2, 0x346e2019, 0x11d01582, 0x9fc4baf6, 0xff7ee723, 0x1f157137,
      0xd36b699d, 0xfba62720, 0x1152c81f, 0x8ae80ce9, 0x56a0da8a, 0x3b7497d5,
      0xa7b2009f, 0x559be587, 0xe768d2d2, 0x4d46ba7e, 0x1daa4c58, 0xd9c6f4c4,
      0xb2ac5e71, 0x5910a786, 0x674c04cd, 0xf243fab1, 0xcbe00a1b, 0x136aa629,
      0x870f290d, 0x68c28a54, 0xf1f37422, 0x61cc6f87, 0x2d80e624, 0x6f5710a0,
      0x16b0fd98, 0x4e94de48, 0xe94e1c48, 0x33393293, 0xcc8ff38f, 0xbad57995,
      0x867821ef, 0x1ad691f8, 0x5b597231, 0x305c759b, 0x21b4daae, 0xee0d61e6,
      0x95c1aa8a, 0xc7caa0c3, 0xa8e813b4, 0x6f0f744f,
  };
  static const uint32_t kCtsRsaPssSha384Sig[kRsa2048NumWords] = {
      0x89385f7c, 0x184b7d66, 0xb275deaf, 0x38e7d099, 0xd8c461c3, 0xc09492fa,
      0x3cd00888, 0x7e50487c, 0x32685ffc, 0x4c05755e, 0xe2e620a5, 0x72e9a114,
      0x6cce6e9a, 0xa05d67aa, 0xc2cdb9fe, 0xdf67def2, 0x630e45b8, 0x4fc217b1,
      0xdc9f2bcd, 0xee7e798e, 0x34d439ee, 0x86a38c5c, 0x77cb1c5f, 0xaeed6fc5,
      0xb3328dbc, 0x81456e84, 0x6fb692a3, 0x2ffbe1e4, 0xf28d6004, 0xb343b6c1,
      0x4d9bfb93, 0x63e1d63b, 0xaacd6a6a, 0x6d3914e6, 0xd3ab4438, 0xae30d836,
      0xf4fee3bd, 0xa6821157, 0xac529ec6, 0x976342e6, 0x4520f95a, 0x3ff6a4d0,
      0x09a59d21, 0x45a5a903, 0x1ff18243, 0xafd2928a, 0x02232314, 0x3e43853e,
      0xa4977153, 0xda1f9660, 0x8d6e29e7, 0x50818584, 0xe26bf069, 0x537a3524,
      0x9115577c, 0x1fb16285, 0xad6f9f41, 0x81e7dcdd, 0x09788599, 0x3f5aaf80,
      0xf8811d95, 0x87a707b2, 0x62ad4b04, 0x8e579923,
  };
  static const uint32_t kCtsRsaPssSha512Sig[kRsa2048NumWords] = {
      0x70106aad, 0xe9fe9f06, 0xd81c0f4d, 0x4233b29e, 0x275c172e, 0xd8e170b8,
      0x0a9cddaa, 0xc57a2dab, 0xfdf72171, 0x325d46bd, 0x1138027d, 0xf9a35849,
      0x253b0698, 0x1a1aad30, 0x605228f6, 0x224fd323, 0xc4c87e36, 0xdc97466c,
      0x9b2a957e, 0xb1048ed9, 0x28de0ee9, 0xd7de976b, 0x1854c5c3, 0xa70425ee,
      0x0371dcf0, 0xd71410e2, 0x136d2790, 0x9388845b, 0x9e9196aa, 0x1fc40a35,
      0x325b6fb6, 0xb4922fb3, 0x8ca9d8c2, 0x8d2e19bc, 0x5b6db4f5, 0x9c385ca5,
      0x7e9ef58f, 0x5d1054c9, 0xae23307b, 0x5490e5f8, 0x04100dd4, 0xdf586b40,
      0x7cde5626, 0x0d951133, 0x10e5b3da, 0x9f482267, 0x7c140c57, 0x5bb7c055,
      0xfbb47fbb, 0x888715c4, 0x3e939f30, 0x4b392dbb, 0x8f46f223, 0x70c8dcc9,
      0xd3b175dc, 0xc745ed42, 0x178ea4ab, 0xba123ebf, 0x328aab4e, 0x9295a0f0,
      0x0c713826, 0x702df052, 0x797beda0, 0x7a40f9f2,
  };
  static const uint8_t kCtsSigMsg[23] = {
      0xec, 0x17, 0x47, 0x29, 0xc4, 0xf5, 0xc5, 0x70, 0xba, 0x0d, 0xe4, 0xc4,
      0x24, 0xcd, 0xcb, 0xf0, 0x36, 0x2a, 0x77, 0x18, 0x03, 0x94, 0x64,
  };
  otcrypto_const_byte_buf_t cts_msg_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_const_byte_buf_t, kCtsSigMsg, sizeof(kCtsSigMsg));
  TRY(otcrypto_sha1(&cts_msg_buf, &sha1_digest));
  TRY(otcrypto_sha2_256(&cts_msg_buf, &sha256_digest));
  TRY(otcrypto_sha2_384(&cts_msg_buf, &sha384_digest));
  TRY(otcrypto_sha2_512(&cts_msg_buf, &sha512_digest));
  const otcrypto_hash_digest_t kCtsDigests[4] = {sha1_digest, sha256_digest,
                                                 sha384_digest, sha512_digest};
  const uint32_t *const kCtsPkcs1Sigs[4] = {
      kCtsRsaPkcs1Sha1Sig, kCtsRsaPkcs1Sha256Sig, kCtsRsaPkcs1Sha384Sig,
      kCtsRsaPkcs1Sha512Sig};
  const uint32_t *const kCtsPssSigs[4] = {
      kCtsRsaPssSha1Sig, kCtsRsaPssSha256Sig, kCtsRsaPssSha384Sig,
      kCtsRsaPssSha512Sig};

  otcrypto_const_word32_buf_t key1_mod = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaKey1Modulus, kRsa2048NumWords);
  otcrypto_const_word32_buf_t key1_d0 = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaKey1PrivExp, kRsa2048NumWords);
  uint32_t zero_share[kRsa2048NumWords] = {0};
  otcrypto_const_word32_buf_t key1_d1 = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, zero_share, kRsa2048NumWords);

  public_key = (otcrypto_unblinded_key_t){
      .key_mode = kOtcryptoKeyModeRsaSignPkcs,
      .key_length = kOtcryptoRsa2048PublicKeyBytes,
      .key = pub_data,
  };
  TRY(otcrypto_rsa_public_key_construct(kOtcryptoRsaSize2048, &key1_mod,
                                        &public_key));
  private_key = (otcrypto_blinded_key_t){
      .config =
          {
              .version = otcrypto_lib_version(),
              .key_mode = kOtcryptoKeyModeRsaSignPkcs,
              .key_length = kOtcryptoRsa2048PrivateKeyBytes,
              .hw_backed = kHardenedBoolFalse,
              .security_level = kOtcryptoKeySecurityLevelLow,
          },
      .keyblob = priv_blob,
      .keyblob_length = kOtcryptoRsa2048PrivateKeyblobBytes,
  };
  TRY(otcrypto_rsa_private_key_from_exponents(
      kOtcryptoRsaSize2048, &key1_mod, &key1_d0, &key1_d1, &private_key));

  for (size_t d = 0; d < ARRAYSIZE(kCtsDigests); ++d) {
    uint32_t sig[kRsa2048NumWords];
    otcrypto_word32_buf_t sig_buf =
        OTCRYPTO_MAKE_BUF(otcrypto_word32_buf_t, sig, ARRAYSIZE(sig));
    TRY(otcrypto_rsa_sign(&private_key, kCtsDigests[d], kOtcryptoRsaPaddingPkcs,
                          &sig_buf));
    TRY_CHECK_ARRAYS_EQ(sig, kCtsPkcs1Sigs[d], kRsa2048NumWords);

    otcrypto_const_word32_buf_t kat_sig_buf = OTCRYPTO_MAKE_BUF(
        otcrypto_const_word32_buf_t, kCtsPkcs1Sigs[d], kRsa2048NumWords);
    hardened_bool_t verif_ok = kHardenedBoolFalse;
    TRY(otcrypto_rsa_verify(&public_key, kCtsDigests[d],
                            kOtcryptoRsaPaddingPkcs, &kat_sig_buf, &verif_ok));
    TRY_CHECK(verif_ok == kHardenedBoolTrue);
  }

  public_key.key_mode = kOtcryptoKeyModeRsaSignPss;
  TRY(otcrypto_rsa_public_key_construct(kOtcryptoRsaSize2048, &key1_mod,
                                        &public_key));
  for (size_t d = 0; d < ARRAYSIZE(kCtsDigests); ++d) {
    otcrypto_const_word32_buf_t kat_pss_buf = OTCRYPTO_MAKE_BUF(
        otcrypto_const_word32_buf_t, kCtsPssSigs[d], kRsa2048NumWords);
    hardened_bool_t verif_ok = kHardenedBoolFalse;
    TRY(otcrypto_rsa_verify(&public_key, kCtsDigests[d], kOtcryptoRsaPaddingPss,
                            &kat_pss_buf, &verif_ok));
    TRY_CHECK(verif_ok == kHardenedBoolTrue);
  }

  // Verify `NONEwithRSA` (`SignatureTest.java:132-139`) directly via
  // high-level `otcrypto_rsa_sign` and `otcrypto_rsa_verify` with
  // `kOtcryptoKeyModeRsaSignPkcs` and `kOtcryptoHashModeNull`.
  // Note: Because `otcrypto_hash_digest_t.len` is measured in 32-bit words,
  // `otcrypto` cannot represent the 23-byte non-word-aligned `kCtsSigMsg`
  // and instead signs/verifies 24 bytes (6 words).
  public_key.key_mode = kOtcryptoKeyModeRsaSignPkcs;
  TRY(otcrypto_rsa_public_key_construct(kOtcryptoRsaSize2048, &key1_mod,
                                        &public_key));
  uint32_t none_msg_words[(sizeof(kCtsSigMsg) + sizeof(uint32_t) - 1) /
                          sizeof(uint32_t)] = {0};
  memcpy(none_msg_words, kCtsSigMsg, sizeof(kCtsSigMsg));
  otcrypto_hash_digest_t none_digest = {
      .mode = kOtcryptoHashModeNull,
      .data = none_msg_words,
      .len = ARRAYSIZE(none_msg_words),
  };
  otcrypto_const_word32_buf_t kat_none_sig_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaNoneSig, kRsa2048NumWords);
  hardened_bool_t none_verif_ok = kHardenedBoolFalse;
  uint32_t none_sig[kRsa2048NumWords];
  otcrypto_word32_buf_t none_sig_buf =
      OTCRYPTO_MAKE_BUF(otcrypto_word32_buf_t, none_sig, ARRAYSIZE(none_sig));
  otcrypto_status_t none_sign_st = otcrypto_rsa_sign(
      &private_key, none_digest, kOtcryptoRsaPaddingPkcs, &none_sig_buf);
  otcrypto_status_t none_verif_st =
      otcrypto_rsa_verify(&public_key, none_digest, kOtcryptoRsaPaddingPkcs,
                          &kat_none_sig_buf, &none_verif_ok);
  TRY(none_sign_st);
  TRY(none_verif_st);
  TRY_CHECK(none_verif_ok == kHardenedBoolTrue);
  TRY_CHECK_ARRAYS_EQ(none_sig, kCtsRsaNoneSig, kRsa2048NumWords);

  return OK_STATUS();
}

/**
 * Source:
 *   - `KeyMintTest.cpp:5410` —
 *     `TEST_P(EncryptionOperationsTest, RsaNoPaddingSuccess)`
 *   - `KeyMintTest.cpp:5439` —
 *     `TEST_P(EncryptionOperationsTest, RsaNoPaddingShortMessage)`
 *   - `KeyMintTest.cpp:5463` —
 *     `TEST_P(EncryptionOperationsTest, RsaOaepSuccess)`
 *   - `KeyMintTest.cpp:5525` —
 *     `TEST_P(EncryptionOperationsTest, RsaOaepInvalidDigest)`
 *   - `KeyMintTest.cpp:5561` —
 *     `TEST_P(EncryptionOperationsTest, RsaOaepDecryptWithWrongDigest)`
 *   - `KeyMintTest.cpp:5801` —
 *     `TEST_P(EncryptionOperationsTest, RsaPkcs1Success)`
 */
static status_t rsa_vts_encryption_modes_test(void) {
  LOG_INFO(
      "Testing EncryptionOperationsTest.RsaNoPadding*, RsaPkcs1*, RsaOaep*");
  uint32_t pub_data[ceil_div(kOtcryptoRsa2048PublicKeyBytes, sizeof(uint32_t))];
  uint32_t priv_blob[ceil_div(kOtcryptoRsa2048PrivateKeyblobBytes,
                              sizeof(uint32_t))];
  otcrypto_unblinded_key_t public_key;
  otcrypto_blinded_key_t private_key;

  uint32_t ciphertext[kRsa2048NumWords];
  otcrypto_word32_buf_t ct_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_word32_buf_t, ciphertext, ARRAYSIZE(ciphertext));
  otcrypto_const_word32_buf_t const_ct_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, ciphertext, ARRAYSIZE(ciphertext));
  otcrypto_const_byte_buf_t empty_label =
      OTCRYPTO_MAKE_BUF(otcrypto_const_byte_buf_t, NULL, 0);
  otcrypto_const_byte_buf_t label_buf =
      OTCRYPTO_MAKE_BUF(otcrypto_const_byte_buf_t, kTestLabel, kTestLabelLen);

  uint8_t decrypted[kRsa2048NumBytes];
  size_t decrypted_len = 0;

  // 1. PKCS#1 v1.5 Encryption (`kOtcryptoKeyModeRsaEncryptPkcs`):
  // Test max message length (245B) and rejection of 246B.
  TRY(construct_rsa2048_keypair(kOtcryptoKeyModeRsaEncryptPkcs, pub_data,
                                &public_key, priv_blob, &private_key));
  uint8_t max_pkcs_msg[kMaxPkcs1v15PayloadBytes];
  for (size_t i = 0; i < sizeof(max_pkcs_msg); ++i) {
    max_pkcs_msg[i] = (uint8_t)(i ^ 0xa5);
  }
  otcrypto_const_byte_buf_t max_pkcs_in = OTCRYPTO_MAKE_BUF(
      otcrypto_const_byte_buf_t, max_pkcs_msg, sizeof(max_pkcs_msg));
  otcrypto_byte_buf_t pkcs_pt_out = OTCRYPTO_MAKE_BUF(
      otcrypto_byte_buf_t, decrypted, kMaxPkcs1v15PayloadBytes);

  TRY(otcrypto_rsa_encrypt(&public_key, kOtcryptoHashModeNull, &max_pkcs_in,
                           &empty_label, &ct_buf));
  TRY(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeNull, &const_ct_buf,
                           &empty_label, &pkcs_pt_out, &decrypted_len));
  TRY_CHECK(decrypted_len == sizeof(max_pkcs_msg));
  TRY_CHECK_ARRAYS_EQ(decrypted, max_pkcs_msg, decrypted_len);

  uint8_t too_long_pkcs[kMaxPkcs1v15PayloadBytes + 1] = {0};
  otcrypto_const_byte_buf_t too_long_in = OTCRYPTO_MAKE_BUF(
      otcrypto_const_byte_buf_t, too_long_pkcs, sizeof(too_long_pkcs));
  TRY_CHECK(otcrypto_rsa_encrypt(&public_key, kOtcryptoHashModeNull,
                                 &too_long_in, &empty_label, &ct_buf)
                .value == OTCRYPTO_BAD_ARGS.value);

  // 2. Raw RSA Encryption (`kOtcryptoKeyModeRsaRaw`):
  TRY(construct_rsa2048_keypair(kOtcryptoKeyModeRsaRaw, pub_data, &public_key,
                                priv_blob, &private_key));
  uint8_t raw_pt[kRsa2048NumBytes] = {0};
  memcpy(raw_pt, kTestMessage, kTestMessageLen);
  otcrypto_const_byte_buf_t raw_in =
      OTCRYPTO_MAKE_BUF(otcrypto_const_byte_buf_t, raw_pt, sizeof(raw_pt));
  otcrypto_byte_buf_t raw_out =
      OTCRYPTO_MAKE_BUF(otcrypto_byte_buf_t, decrypted, sizeof(decrypted));

  TRY(otcrypto_rsa_encrypt(&public_key, kOtcryptoHashModeNull, &raw_in,
                           &empty_label, &ct_buf));
  decrypted_len = 0;
  TRY(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeNull, &const_ct_buf,
                           &empty_label, &raw_out, &decrypted_len));
  TRY_CHECK(decrypted_len == kRsa2048NumBytes);
  TRY_CHECK_ARRAYS_EQ(decrypted, raw_pt, kRsa2048NumBytes);

  // 3. RSA-OAEP with SHA-1, SHA-256, SHA-384, and SHA-512 (with label and
  // wrong-label failure):
  TRY(construct_rsa2048_keypair(kOtcryptoKeyModeRsaEncryptOaep, pub_data,
                                &public_key, priv_blob, &private_key));
  otcrypto_const_byte_buf_t msg_in = OTCRYPTO_MAKE_BUF(
      otcrypto_const_byte_buf_t, kTestMessage, kTestMessageLen);
  const otcrypto_hash_mode_t kOaepHashes[4] = {
      kOtcryptoHashModeSha1, kOtcryptoHashModeSha256, kOtcryptoHashModeSha384,
      kOtcryptoHashModeSha512};

  for (size_t h = 0; h < ARRAYSIZE(kOaepHashes); ++h) {
    TRY(otcrypto_rsa_encrypt(&public_key, kOaepHashes[h], &msg_in, &label_buf,
                             &ct_buf));
    decrypted_len = 0;
    TRY(otcrypto_rsa_decrypt(&private_key, kOaepHashes[h], &const_ct_buf,
                             &label_buf, &raw_out, &decrypted_len));
    TRY_CHECK(decrypted_len == kTestMessageLen);
    TRY_CHECK_ARRAYS_EQ(decrypted, kTestMessage, kTestMessageLen);

    // Decrypting with a mismatched OAEP label must fail.
    TRY_CHECK(otcrypto_rsa_decrypt(&private_key, kOaepHashes[h], &const_ct_buf,
                                   &empty_label, &raw_out, &decrypted_len)
                  .value == OTCRYPTO_BAD_ARGS.value);
  }

  // KeyMintTest.cpp:5497 (`RsaOaepSuccess`), 5525 (`RsaOaepInvalidDigest`),
  // & 5561 (`RsaOaepDecryptWithWrongDigest`):
  // - OAEP encryption is randomized (`ciphertext1 != ciphertext2`).
  uint32_t ciphertext2[kRsa2048NumWords];
  otcrypto_word32_buf_t ct2_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_word32_buf_t, ciphertext2, ARRAYSIZE(ciphertext2));
  TRY(otcrypto_rsa_encrypt(&public_key, kOtcryptoHashModeSha1, &msg_in,
                           &empty_label, &ct_buf));
  TRY(otcrypto_rsa_encrypt(&public_key, kOtcryptoHashModeSha1, &msg_in,
                           &empty_label, &ct2_buf));
  TRY_CHECK(memcmp(ciphertext, ciphertext2, sizeof(ciphertext)) != 0);

  // - `RsaOaepInvalidDigest`: OAEP with `Digest::NONE`
  // (`kOtcryptoHashModeNull`)
  //   fails with `OTCRYPTO_BAD_ARGS`.
  TRY_CHECK(otcrypto_rsa_encrypt(&public_key, kOtcryptoHashModeNull, &msg_in,
                                 &empty_label, &ct_buf)
                .value == OTCRYPTO_BAD_ARGS.value);

  // - `RsaOaepDecryptWithWrongDigest`: Encrypt with SHA-1 (`ct_buf`), decrypt
  //   with SHA-256 fails with `OTCRYPTO_BAD_ARGS`.
  TRY_CHECK(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeSha256,
                                 &const_ct_buf, &empty_label, &raw_out,
                                 &decrypted_len)
                .value == OTCRYPTO_BAD_ARGS.value);

  // 4. Android CTS `CipherTest.java:192-270` (`KAT_VECTORS`) using
  // `R.raw.rsa_key2_pkcs8`:
  static const uint32_t kCtsRsaKey2Modulus[kRsa2048NumWords] = {
      0x6d2eb95d, 0xe8f2d3fd, 0x4fbde5fd, 0x3ce6f0d2, 0x7c79ae8f, 0x1b4fcdc4,
      0xabdad957, 0x696d8e92, 0xff22aa71, 0x7ea1b175, 0xb3e5ff3e, 0x0f822e6b,
      0x2c9c6210, 0xeeb5ddc4, 0x13675d62, 0x70729231, 0x92070869, 0x87fef983,
      0x9319f263, 0x6d86a6a6, 0x9dd0c843, 0x72844336, 0x99124a90, 0x5123f029,
      0xddac2a7d, 0xcba94685, 0x7d363e99, 0xef32f2a1, 0x62dfd58b, 0xf0102a09,
      0x246c4e06, 0x8cbe4af2, 0xf243082f, 0x7904912d, 0x0ff549e1, 0x04371322,
      0xcecbb8c5, 0x17ff59a8, 0xd674703d, 0x68646f63, 0x33425dc6, 0xfa16119b,
      0x90b8caa2, 0x9bf3bba5, 0xef0ece3b, 0xa468a834, 0x702c965a, 0xc97ccc90,
      0xb73b4462, 0xb4330506, 0xd4be8f9a, 0x9f7fa586, 0xca828ccd, 0xbcd3fd2f,
      0x393a9dea, 0x3945db5d, 0x3b1485a0, 0x77d2be35, 0x47f873f7, 0xde98a946,
      0xba7980ee, 0xf49a096e, 0xae39a4d0, 0xaba43abc,
  };
  static const uint32_t kCtsRsaKey2PrivExp[kRsa2048NumWords] = {
      0xed8dd741, 0x7929539f, 0xadadd559, 0x74cd3830, 0x7ecb8017, 0x55f8b23b,
      0x53e332b5, 0xf2d3a20b, 0xb9ecbe08, 0xe485d15a, 0xe1be6370, 0xaf5a0fa8,
      0x7a6b16f2, 0xf203a7dd, 0xc840af6b, 0x82a9e386, 0xc0ef1390, 0x4a502cfd,
      0x750c7232, 0x4bf9fc70, 0x424a2fc8, 0x4e52abe8, 0xe22bafdb, 0x04f11b20,
      0xdeab2fbc, 0x7e6d2386, 0x22af86ef, 0x951431df, 0xb493daed, 0x1fef4a86,
      0xbd151d56, 0xa3bf1869, 0xe408993d, 0x305d09d3, 0x50863953, 0xba1965ae,
      0x24cb346c, 0x1de07e4f, 0x0f2f09df, 0x0cd26c18, 0xbf8bc6a6, 0x355a3675,
      0xf4e67ac8, 0x8e2967a3, 0x176ce734, 0x3bf315a2, 0xaf6e540f, 0x575db662,
      0x61f5e621, 0x10d96b91, 0x722b4194, 0xc144038d, 0x62c73390, 0x4a48462f,
      0x36075a35, 0xb2b85dd2, 0x4298ebde, 0xa0f75624, 0x4781cead, 0x46ad0add,
      0xc3aa214d, 0xab2c680f, 0xf5402364, 0x3576dc8c,
  };
  static const uint8_t kCtsRsaNoPadPt[47] = {
      0x50, 0xc4, 0x99, 0xd5, 0x58, 0xc3, 0x8f, 0xd4, 0x8e, 0xa7, 0x68, 0x32,
      0x88, 0x7d, 0xb2, 0xab, 0xc7, 0x6e, 0x4e, 0x15, 0x3a, 0x98, 0xfd, 0x43,
      0x23, 0xcc, 0xb8, 0x00, 0x6d, 0x34, 0xf1, 0x17, 0x24, 0xa5, 0x69, 0x2f,
      0xb1, 0x01, 0xb0, 0xeb, 0x96, 0x06, 0x0e, 0xb9, 0xd1, 0x52, 0x22,
  };
  static const uint32_t kCtsRsaNoPadCt[kRsa2048NumWords] = {
      0xfa650697, 0xede206ac, 0xd9fbaadd, 0x5ddebf92, 0x6a7acbe1, 0x9efdeed8,
      0xe2bb3376, 0xd7188fe7, 0xe56092ee, 0x5914ce4b, 0xddac7584, 0x9636d67c,
      0x2e90041e, 0xf8ee427f, 0x9e3b6fe6, 0x1da22902, 0x337b1603, 0xc333d131,
      0xd6ac6fd6, 0x73cdec88, 0xb97c0565, 0x0aafbb9e, 0x63417bc0, 0x01278c66,
      0x6cf21444, 0x264896fb, 0x8c56eeff, 0x1e5c3aea, 0xa0fec4d0, 0xa5a5dac1,
      0xd2a2f98e, 0x92dc3d32, 0xb07f00b2, 0x99d8de02, 0x838c0d43, 0x4cc2dd78,
      0x475afeba, 0xd9ec750f, 0x7de7bfe9, 0xe7e505dc, 0x3df0d98b, 0x7c343295,
      0xe41297b8, 0xfb0ac585, 0x4ed17099, 0xa03f95e1, 0xa51e6293, 0x32778592,
      0x5cc69ced, 0x5f5ba27e, 0x5c13dc40, 0x098318e5, 0x25e6ae5e, 0xb1654aab,
      0x592ede29, 0xd822d369, 0x223e3f78, 0xc67cf535, 0xe26148d7, 0xb1b8ef8e,
      0x80bbc0cb, 0xb3f23276, 0x61e98d0a, 0x349b1d50,
  };
  static const uint8_t kCtsRsaPkcs1Pt[50] = {
      0xae, 0xd8, 0xcd, 0x94, 0xf3, 0x5b, 0x2a, 0x54, 0xcd, 0xd3,
      0xed, 0x77, 0x14, 0x82, 0xbd, 0x87, 0xe2, 0x56, 0xb9, 0x95,
      0x40, 0x85, 0x58, 0xfb, 0x82, 0xe5, 0xd4, 0x75, 0xd1, 0xee,
      0x54, 0x71, 0x14, 0x72, 0xf8, 0x99, 0xad, 0x6c, 0xbb, 0x68,
      0x47, 0x99, 0xe5, 0x2f, 0xf1, 0xd5, 0x7c, 0xbc, 0x39, 0xf4,
  };
  static const uint32_t kCtsRsaPkcs1Ct[kRsa2048NumWords] = {
      0xdbfd5978, 0xe20fb1a9, 0x37a74df3, 0x2ef82fbe, 0xcf7b678a, 0x43da6e1d,
      0x75c9f5b1, 0x444b011d, 0x0589d7d0, 0x60557a0c, 0xb47e43e9, 0x9fd6e752,
      0xb98ad797, 0x945d6491, 0xe46a939a, 0xabae1475, 0x774b7486, 0x1958e5a0,
      0x113d2489, 0x2213c1cc, 0x99e86b0b, 0x82cf484d, 0xc68ace91, 0x9c199ee2,
      0x0f83c4f8, 0xcbb2642e, 0xcabd53a2, 0x5010834f, 0x59651433, 0xd9ccec4c,
      0x6f59f351, 0x8928949b, 0x4351d060, 0x19c628fd, 0x12113167, 0xadd20f52,
      0x3f9fb74a, 0x413d2706, 0x8a242737, 0xcd494a5c, 0xb7f39079, 0x226bc806,
      0x7530c162, 0x33f24b72, 0x420d0ea4, 0x49061319, 0x51cb4caa, 0xed5b70da,
      0x157af0d2, 0xdbe3103c, 0x2df9c703, 0xb95a2df0, 0xc5eca522, 0xcb267938,
      0x4d3cfde3, 0xeb1e6b5f, 0xe8993e73, 0x559087d6, 0x71393cf6, 0xcf90c89f,
      0xea661318, 0x31d2b595, 0x294dd3ea, 0x64148dee,
  };
  static const uint8_t kCtsRsaOaepDefPt[30] = {
      0xc2, 0x19, 0xf4, 0xe3, 0xe3, 0x7e, 0xae, 0x23, 0x15, 0xf0,
      0xfa, 0x4e, 0xbc, 0x4b, 0x46, 0xef, 0x0c, 0x6b, 0xef, 0xbb,
      0x43, 0xa5, 0x1c, 0xed, 0xa0, 0x74, 0x35, 0xfc, 0x88, 0xa9,
  };
  static const uint32_t kCtsRsaOaepDefCt[kRsa2048NumWords] = {
      0x86323e89, 0xcbf27701, 0x7e9b5617, 0xc90d2e27, 0xd3c094d5, 0x1d1ddac4,
      0xa4167f72, 0xfbd24ab5, 0xb9c3b1d1, 0x5965a7e0, 0x05733135, 0xa377b502,
      0x4f24504c, 0x71313ea9, 0x3c6e93c4, 0xd0f6b872, 0x0be4a4a6, 0x4a51a9e9,
      0x5848b165, 0x72e1376e, 0xd0007794, 0xa1d8e517, 0xdb6ae453, 0xfab9e3cd,
      0x4dc70c25, 0x771abe4e, 0x87eb45b5, 0xb5e87d31, 0x6d7595ba, 0xdc9bd919,
      0x883af0dc, 0xb774797f, 0x04a3eb3d, 0x81bf6977, 0x6ca6b08f, 0x57d6bc55,
      0x808350f9, 0xf87bf9a5, 0x94e893ff, 0xa4115c3e, 0xe10885b3, 0x0a640a49,
      0xf0df503a, 0xe394ad1d, 0x70e9966d, 0xeeaedfd9, 0xdcc83ac8, 0x439ed2ed,
      0xf3e66239, 0xe4e56cfe, 0xab20dd60, 0x728a0c0f, 0x5171c2c3, 0xf260ad6e,
      0x8324294b, 0xe13de82c, 0xc2f17dde, 0xb404bc0f, 0xca7cced8, 0x118a4a3b,
      0xa09c2dad, 0x025bbf5b, 0xd02b6434, 0x7a9bcfd0,
  };
  static const uint8_t kCtsRsaOaepSha1Pt[45] = {
      0xbb, 0x28, 0x54, 0x62, 0x0b, 0xb0, 0xe3, 0x61, 0xd1, 0x38, 0x47, 0x03,
      0xdd, 0xa1, 0x2a, 0xce, 0xe1, 0xfe, 0xfc, 0x22, 0x02, 0x4b, 0xcf, 0xc4,
      0x0a, 0x86, 0x39, 0x0d, 0x53, 0x42, 0xc6, 0x93, 0xaa, 0xb8, 0xc7, 0xed,
      0x65, 0x17, 0xd8, 0xda, 0x86, 0x04, 0x49, 0x2c, 0x9d,
  };
  static const uint32_t kCtsRsaOaepSha1Ct[kRsa2048NumWords] = {
      0x948b723a, 0xcd26c936, 0xff62b927, 0x2e160c1b, 0xb1051b46, 0x08e0e98a,
      0xdd49346b, 0x32b2f5bb, 0xbdb85940, 0x4d77fa77, 0x5db977af, 0xfcb1a60d,
      0x5b44acf4, 0x00be713b, 0xa44ff0d8, 0x7b0ab144, 0xfe2a01a3, 0x740216ee,
      0xf8c9d946, 0x5de5a0a6, 0x7e1f5210, 0x67365915, 0xa15c1ccf, 0x5a46be99,
      0x335a6817, 0x34291fe4, 0x07f2d35e, 0x5040bbfb, 0xbe0e4521, 0x12af27d7,
      0x16313fe0, 0x5730e6dc, 0xd98b13d4, 0x958ed386, 0xc5598ac7, 0xe0cfd161,
      0xa198f27a, 0xebaa7127, 0xf05ddc45, 0xaff95876, 0xe0c98b07, 0x49d3f049,
      0xb3bfc58c, 0xa8f3cd42, 0x03e7681f, 0xe564cb0d, 0xc24a818d, 0x7c93649b,
      0xdaf660fc, 0x86f2785c, 0xb39407ff, 0xaf5b9560, 0x6ea2e189, 0x2da79aa8,
      0xa8b37db4, 0x7dd5e567, 0xbaa8a3ae, 0x87a269ca, 0x62f67ce9, 0xf0505e75,
      0xc6f7c3f9, 0xd93bfe6d, 0x8f24ef0e, 0x77033c57,
  };
  static const uint8_t kCtsRsaOaepSha256Pt[63] = {
      0x33, 0x2c, 0x2f, 0x2f, 0xc0, 0x66, 0xfb, 0x29, 0xec, 0x09, 0x28,
      0xa5, 0x2b, 0x51, 0x11, 0xce, 0x69, 0x65, 0x54, 0x6c, 0xe7, 0x39,
      0x27, 0x34, 0x0c, 0x42, 0xd3, 0x3b, 0x56, 0xb6, 0xba, 0x54, 0x7b,
      0x77, 0xac, 0x36, 0x1a, 0xc0, 0xd1, 0x33, 0x16, 0x34, 0x5c, 0xa9,
      0x53, 0x84, 0x00, 0x23, 0xd8, 0x92, 0xfa, 0x4f, 0xf1, 0xaa, 0x32,
      0xcc, 0x66, 0xd5, 0xaa, 0x88, 0xb7, 0x98, 0x67,
  };
  static const uint32_t kCtsRsaOaepSha256Ct[kRsa2048NumWords] = {
      0xe1862d74, 0x9dd5173e, 0xd4adb150, 0xdd8d517a, 0x09069468, 0x5d11de90,
      0xa8ba573f, 0x7f45e346, 0x845fdc7c, 0xd85ce423, 0x1d100e67, 0x0b1631be,
      0x9c7fb350, 0x4231c6b7, 0x75d5d755, 0x456dd406, 0xa57cfbfa, 0xacd8ddd3,
      0x49ae44d3, 0x27954f0e, 0x4b50a825, 0x271ddb8c, 0x213f3f24, 0x1683d237,
      0xec0d89bb, 0x8f1d62ed, 0xb791c497, 0xa57ead6d, 0x7519df66, 0x7d947ff9,
      0x1da880c2, 0xb029f1e3, 0xc18bbf55, 0x51230c6b, 0xdf1e6ce6, 0x388128b6,
      0xbfc7b86f, 0xbb4fd7f3, 0x48eb86bb, 0x1efe9c55, 0x1e94abc5, 0x903915e0,
      0x022be6a0, 0xb2203799, 0x077afec7, 0xfcf05bb2, 0x55577b34, 0x38c460c7,
      0xee6efbfe, 0xd5883ff8, 0x0a28873f, 0xa8dfe4cb, 0xae84fb40, 0x715a3d95,
      0xd2f33200, 0xaddcd3e5, 0xa57307a9, 0x6d4f0f63, 0x58faf1b2, 0x4c66bc14,
      0x1b1df508, 0xe116d928, 0xc67a34a7, 0x942c0ba1,
  };
  static const uint8_t kCtsRsaOaepSha384Pt[55] = {
      0xf5, 0x1f, 0x15, 0x8c, 0xba, 0xd4, 0xdb, 0xab, 0x38, 0x40, 0x3b,
      0x83, 0x9c, 0x72, 0x4f, 0x09, 0xa4, 0x80, 0xc4, 0x9b, 0xe2, 0x9c,
      0x0e, 0x72, 0x61, 0x55, 0x39, 0xdb, 0xe5, 0x7e, 0xc8, 0x61, 0x43,
      0xf3, 0x1f, 0x19, 0x39, 0x2f, 0x41, 0x9b, 0x5b, 0xe4, 0xba, 0x9e,
      0x3c, 0x6f, 0x1e, 0x87, 0x0d, 0x30, 0x7a, 0x7c, 0xf1, 0xa9, 0xe2,
  };
  static const uint32_t kCtsRsaOaepSha384Ct[kRsa2048NumWords] = {
      0x56b782f5, 0x0bdcfb3f, 0x7570410f, 0x458976ff, 0x3deff9d0, 0x6153da35,
      0x01d00f08, 0x62094473, 0x598da9bd, 0x5ed541f1, 0x03e916da, 0x5f0ed8cd,
      0x4a3c5e88, 0x699e2455, 0x995153e8, 0x872f9975, 0xcd983121, 0xb397d0b3,
      0x7becc84d, 0xb966fc00, 0xb5d47aad, 0x18a61ae1, 0xd385a1e7, 0x75a3eb30,
      0x161ac13d, 0xa51fcef8, 0x600eb3cd, 0x4c6ca897, 0xec50bb46, 0x5543c00d,
      0xd8072575, 0x445e201a, 0x07e5018e, 0xc24439c1, 0xa3d1fbe2, 0x5be79eb8,
      0xfe2566ec, 0x2828cb75, 0x0ec00da6, 0x4e607244, 0xa6d7f705, 0x02cfb110,
      0x854bfa38, 0x725a4e45, 0x4cb8a54d, 0x6b6f09ba, 0x9d176533, 0xc13540df,
      0x26306af9, 0xc73be527, 0x8ad9fc17, 0x00268839, 0x9b900aaf, 0x5a64108c,
      0xae333ff2, 0x52a848fc, 0x599a02f6, 0xd4760986, 0x4efb9970, 0xf5cdc5bc,
      0x6b6835a4, 0x273e9498, 0x5f534e7a, 0x944243f3,
  };
  static const uint8_t kCtsRsaOaepSha512Pt[87] = {
      0xd4, 0x5f, 0x6c, 0xcc, 0x7e, 0x66, 0x39, 0x57, 0xf2, 0x34, 0xc2,
      0x37, 0xc1, 0xf0, 0x9b, 0xf7, 0x79, 0x1f, 0x6f, 0x5c, 0x1b, 0x9e,
      0xf4, 0xfe, 0xfb, 0x16, 0xe5, 0x5d, 0xed, 0x0d, 0x96, 0x11, 0x2e,
      0x59, 0x0f, 0x1b, 0xb0, 0x8a, 0x60, 0xf8, 0x5c, 0x2d, 0x0d, 0x25,
      0x33, 0xf1, 0xd6, 0x97, 0x92, 0xdf, 0xd8, 0xd6, 0x47, 0xd8, 0x80,
      0xb1, 0x8f, 0x87, 0xcf, 0xe3, 0x24, 0x88, 0xc7, 0x36, 0x13, 0xa3,
      0xd5, 0x35, 0xda, 0x7d, 0x77, 0x6d, 0x90, 0xd9, 0xa4, 0xba, 0x6a,
      0x03, 0x11, 0xf4, 0x56, 0x85, 0x11, 0xda, 0x49, 0x10, 0x7c,
  };
  static const uint32_t kCtsRsaOaepSha512Ct[kRsa2048NumWords] = {
      0xf6785c27, 0x6a6310f1, 0xac7729f1, 0x32ae04ae, 0x80e6032c, 0x111fa62c,
      0xded3a2dc, 0x4c5f38ed, 0xa0358a8f, 0x3fc511ff, 0x414314c1, 0xca9273ad,
      0xa101792a, 0xb0848ddd, 0xdc9b3c3e, 0x38760767, 0xcb23b1d9, 0x28078e12,
      0x6e7a3b73, 0x166d5b50, 0xe4a6e0bf, 0xe517b7b9, 0x283ab114, 0xd8dfe4b1,
      0x32d4377b, 0x1a6c2a03, 0xb1f550f9, 0x6224c876, 0x03ceab97, 0x33a80bc7,
      0x1bfcd3c9, 0xca8231e9, 0x3161dce4, 0x2d796024, 0x4467758f, 0xbc72c876,
      0xaa8833c4, 0xd14a06b8, 0x65f8dce5, 0xf97e865e, 0xfd99409c, 0xe382e6b6,
      0xf7b42506, 0x5f046fc9, 0x9454c2b2, 0xa657e10b, 0x6059667c, 0xb89fbd19,
      0x8d31f376, 0x45d35b18, 0x70998634, 0xf9d2bf4e, 0x7b29876a, 0x7a9136a2,
      0xc69b40a7, 0xbfb444f6, 0x50e27267, 0xade6a09f, 0xbdff67c8, 0x9985e513,
      0xb2aef7c6, 0x03541e2d, 0xe5d6f3f7, 0x5a037df3,
  };
  otcrypto_const_word32_buf_t key2_mod = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaKey2Modulus, kRsa2048NumWords);
  otcrypto_const_word32_buf_t key2_d0 = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaKey2PrivExp, kRsa2048NumWords);
  uint32_t key2_zero_share[kRsa2048NumWords] = {0};
  otcrypto_const_word32_buf_t key2_d1 = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, key2_zero_share, kRsa2048NumWords);

  // 4a. `KAT_VECTORS["RSA/ECB/NoPadding"]` (`CipherTest.java:192-201`):
  public_key = (otcrypto_unblinded_key_t){
      .key_mode = kOtcryptoKeyModeRsaRaw,
      .key_length = kOtcryptoRsa2048PublicKeyBytes,
      .key = pub_data,
  };
  TRY(otcrypto_rsa_public_key_construct(kOtcryptoRsaSize2048, &key2_mod,
                                        &public_key));
  private_key = (otcrypto_blinded_key_t){
      .config =
          {
              .version = otcrypto_lib_version(),
              .key_mode = kOtcryptoKeyModeRsaRaw,
              .key_length = kOtcryptoRsa2048PrivateKeyBytes,
              .hw_backed = kHardenedBoolFalse,
              .security_level = kOtcryptoKeySecurityLevelLow,
          },
      .keyblob = priv_blob,
      .keyblob_length = kOtcryptoRsa2048PrivateKeyblobBytes,
  };
  TRY(otcrypto_rsa_private_key_from_exponents(
      kOtcryptoRsaSize2048, &key2_mod, &key2_d0, &key2_d1, &private_key));

  uint8_t cts_nopad_le[kRsa2048NumBytes] = {0};
  for (size_t i = 0; i < sizeof(kCtsRsaNoPadPt); ++i) {
    cts_nopad_le[i] = kCtsRsaNoPadPt[sizeof(kCtsRsaNoPadPt) - 1 - i];
  }
  otcrypto_const_byte_buf_t cts_nopad_in = OTCRYPTO_MAKE_BUF(
      otcrypto_const_byte_buf_t, cts_nopad_le, sizeof(cts_nopad_le));
  TRY(otcrypto_rsa_encrypt(&public_key, kOtcryptoHashModeNull, &cts_nopad_in,
                           &empty_label, &ct_buf));
  TRY_CHECK_ARRAYS_EQ(ciphertext, kCtsRsaNoPadCt, kRsa2048NumWords);
  otcrypto_const_word32_buf_t cts_nopad_ct_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaNoPadCt, kRsa2048NumWords);
  decrypted_len = 0;
  TRY(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeNull,
                           &cts_nopad_ct_buf, &empty_label, &raw_out,
                           &decrypted_len));
  TRY_CHECK(decrypted_len == kRsa2048NumBytes);
  TRY_CHECK_ARRAYS_EQ(decrypted, cts_nopad_le, kRsa2048NumBytes);

  // 4b. `KAT_VECTORS["RSA/ECB/PKCS1Padding"]` (`CipherTest.java:202-211`):
  private_key.config.key_mode = kOtcryptoKeyModeRsaEncryptPkcs;
  TRY(otcrypto_rsa_private_key_from_exponents(
      kOtcryptoRsaSize2048, &key2_mod, &key2_d0, &key2_d1, &private_key));
  otcrypto_const_word32_buf_t cts_pkcs1_ct_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaPkcs1Ct, kRsa2048NumWords);
  decrypted_len = 0;
  TRY(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeNull,
                           &cts_pkcs1_ct_buf, &empty_label, &pkcs_pt_out,
                           &decrypted_len));
  TRY_CHECK(decrypted_len == sizeof(kCtsRsaPkcs1Pt));
  TRY_CHECK_ARRAYS_EQ(decrypted, kCtsRsaPkcs1Pt, sizeof(kCtsRsaPkcs1Pt));

  // 4c. `KAT_VECTORS["RSA/ECB/OAEPPadding"]` &
  // `KAT_VECTORS["RSA/ECB/OAEPWithSHA-1AndMGF1Padding"]`
  // (`CipherTest.java:212-230`):
  private_key.config.key_mode = kOtcryptoKeyModeRsaEncryptOaep;
  TRY(otcrypto_rsa_private_key_from_exponents(
      kOtcryptoRsaSize2048, &key2_mod, &key2_d0, &key2_d1, &private_key));
  otcrypto_const_word32_buf_t cts_oaep_def_ct_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaOaepDefCt, kRsa2048NumWords);
  decrypted_len = 0;
  TRY(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeSha1,
                           &cts_oaep_def_ct_buf, &empty_label, &raw_out,
                           &decrypted_len));
  TRY_CHECK(decrypted_len == sizeof(kCtsRsaOaepDefPt));
  TRY_CHECK_ARRAYS_EQ(decrypted, kCtsRsaOaepDefPt, sizeof(kCtsRsaOaepDefPt));

  otcrypto_const_word32_buf_t cts_oaep_sha1_ct_buf = OTCRYPTO_MAKE_BUF(
      otcrypto_const_word32_buf_t, kCtsRsaOaepSha1Ct, kRsa2048NumWords);
  decrypted_len = 0;
  TRY(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeSha1,
                           &cts_oaep_sha1_ct_buf, &empty_label, &raw_out,
                           &decrypted_len));
  TRY_CHECK(decrypted_len == sizeof(kCtsRsaOaepSha1Pt));
  TRY_CHECK_ARRAYS_EQ(decrypted, kCtsRsaOaepSha1Pt, sizeof(kCtsRsaOaepSha1Pt));

  // 4d. `KAT_VECTORS["RSA/ECB/OAEPWithSHA-{256,384,512}AndMGF1Padding"]`
  // (`CipherTest.java:240-270`): Android JCA's default OAEP parameter spec
  // uses SHA-256/384/512 as the main digest with `MGF1ParameterSpec.SHA1`
  // (compare `KeyMintTest.cpp:5463` `mgf_digests`). Call high-level
  // `otcrypto_rsa_decrypt` directly (`kOtcryptoKeyModeRsaEncryptOaep`);
  // `otcrypto` currently couples the MGF1 digest to `hash_mode` and does not
  // allow specifying an independent MGF1 digest (`MGF1-SHA1`).
  const struct {
    otcrypto_hash_mode_t main_hash;
    const uint32_t *ct;
    const uint8_t *pt;
    size_t pt_len;
  } kCtsOaepMgf1Sha1Vectors[3] = {
      {kOtcryptoHashModeSha256, kCtsRsaOaepSha256Ct, kCtsRsaOaepSha256Pt,
       sizeof(kCtsRsaOaepSha256Pt)},
      {kOtcryptoHashModeSha384, kCtsRsaOaepSha384Ct, kCtsRsaOaepSha384Pt,
       sizeof(kCtsRsaOaepSha384Pt)},
      {kOtcryptoHashModeSha512, kCtsRsaOaepSha512Ct, kCtsRsaOaepSha512Pt,
       sizeof(kCtsRsaOaepSha512Pt)},
  };
  otcrypto_status_t oaep_kat_status = OTCRYPTO_OK;
  for (size_t v = 0; v < ARRAYSIZE(kCtsOaepMgf1Sha1Vectors); ++v) {
    otcrypto_const_word32_buf_t v_ct_buf =
        OTCRYPTO_MAKE_BUF(otcrypto_const_word32_buf_t,
                          kCtsOaepMgf1Sha1Vectors[v].ct, kRsa2048NumWords);
    decrypted_len = 0;
    otcrypto_status_t st =
        otcrypto_rsa_decrypt(&private_key, kCtsOaepMgf1Sha1Vectors[v].main_hash,
                             &v_ct_buf, &empty_label, &raw_out, &decrypted_len);
    if (!status_ok(st)) {
      if (status_ok(oaep_kat_status)) {
        oaep_kat_status = st;
      }
      continue;
    }
    TRY_CHECK(decrypted_len == kCtsOaepMgf1Sha1Vectors[v].pt_len);
    TRY_CHECK_ARRAYS_EQ(decrypted, kCtsOaepMgf1Sha1Vectors[v].pt,
                        kCtsOaepMgf1Sha1Vectors[v].pt_len);
  }
  TRY(oaep_kat_status);

  return OK_STATUS();
}

/**
 * Source:
 *   - `CipherTest.java:398` — `testEmptyPlaintextEncryptsAndDecrypts`
 *   - `KeyMintTest.cpp:5801` —
 *     `TEST_P(EncryptionOperationsTest, RsaPkcs1Success)` (0-byte message
 *     encryption/decryption and caller buffer sizing)
 *   - `KeyMintTest.cpp:3321` — `TEST_P(SigningOperationsTest, RsaNoDigest)`
 *     (0-byte message signing/verification)
 */
static status_t rsa_vts_cts_empty_plaintext_and_no_digest_test(void) {
  LOG_INFO(
      "Testing Android CTS testEmptyPlaintextEncryptsAndDecrypts & KeyMint VTS "
      "RsaNoDigest (0-byte message)");

  uint32_t pub_data[ceil_div(kOtcryptoRsa2048PublicKeyBytes, sizeof(uint32_t))];
  uint32_t priv_blob[ceil_div(kOtcryptoRsa2048PrivateKeyblobBytes,
                              sizeof(uint32_t))];
  otcrypto_unblinded_key_t public_key;
  otcrypto_blinded_key_t private_key;

  uint32_t sig[kRsa2048NumWords];
  otcrypto_word32_buf_t sig_buf =
      OTCRYPTO_MAKE_BUF(otcrypto_word32_buf_t, sig, ARRAYSIZE(sig));
  otcrypto_const_word32_buf_t const_sig_buf =
      OTCRYPTO_MAKE_BUF(otcrypto_const_word32_buf_t, sig, ARRAYSIZE(sig));

  // 1. `CipherTest.java:398` (`testEmptyPlaintextEncryptsAndDecrypts`) &
  // `KeyMintTest.cpp:5801` (`RsaPkcs1Success`): 0-byte PKCS#1 v1.5
  // encryption/decryption round-trip:
  TRY(construct_rsa2048_keypair(kOtcryptoKeyModeRsaEncryptPkcs, pub_data,
                                &public_key, priv_blob, &private_key));
  otcrypto_const_byte_buf_t empty_pt =
      OTCRYPTO_MAKE_BUF(otcrypto_const_byte_buf_t, NULL, 0);
  otcrypto_const_byte_buf_t empty_label =
      OTCRYPTO_MAKE_BUF(otcrypto_const_byte_buf_t, NULL, 0);
  TRY(otcrypto_rsa_encrypt(&public_key, kOtcryptoHashModeNull, &empty_pt,
                           &empty_label, &sig_buf));

  uint8_t decrypted[kRsa2048NumBytes];
  size_t decrypted_len = 999;
  otcrypto_byte_buf_t max_pkcs_out = OTCRYPTO_MAKE_BUF(
      otcrypto_byte_buf_t, decrypted, kMaxPkcs1v15PayloadBytes);
  TRY(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeNull, &const_sig_buf,
                           &empty_label, &max_pkcs_out, &decrypted_len));
  TRY_CHECK(decrypted_len == 0);

  // 2. Decrypting a 0-byte PKCS#1 v1.5 plaintext into a 64-byte output buffer
  // should succeed (`OTCRYPTO_OK` with `decrypted_len == 0`; currently fails
  // in `rsa_decrypt_finalize` (`rsa_encryption.c:127-137`) because it requires
  // `plaintext_max_bytelen >= k - 11` before inspecting the padding).
  otcrypto_byte_buf_t small_out =
      OTCRYPTO_MAKE_BUF(otcrypto_byte_buf_t, decrypted, 64);
  TRY(otcrypto_rsa_decrypt(&private_key, kOtcryptoHashModeNull, &const_sig_buf,
                           &empty_label, &small_out, &decrypted_len));
  TRY_CHECK(decrypted_len == 0);

  return OK_STATUS();
}

/**
 * Source:
 *   - `KeyMintTest.cpp:3321` — `TEST_P(SigningOperationsTest, RsaNoDigest)`
 *     (0-byte message signing and verification with `RSA_PKCS1_1_5_SIGN` +
 *     `Digest::NONE`)
 */
static status_t rsa_vts_signing_zero_length_no_digest_test(void) {
  LOG_INFO(
      "Testing KeyMint VTS SigningOperationsTest.RsaNoDigest (0-byte message)");

  uint32_t pub_data[ceil_div(kOtcryptoRsa2048PublicKeyBytes, sizeof(uint32_t))];
  uint32_t priv_blob[ceil_div(kOtcryptoRsa2048PrivateKeyblobBytes,
                              sizeof(uint32_t))];
  otcrypto_unblinded_key_t public_key;
  otcrypto_blinded_key_t private_key;

  uint32_t sig[kRsa2048NumWords];
  otcrypto_word32_buf_t sig_buf =
      OTCRYPTO_MAKE_BUF(otcrypto_word32_buf_t, sig, ARRAYSIZE(sig));
  otcrypto_const_word32_buf_t const_sig_buf =
      OTCRYPTO_MAKE_BUF(otcrypto_const_word32_buf_t, sig, ARRAYSIZE(sig));

  // KeyMint VTS `SigningOperationsTest.RsaNoDigest` (`KeyMintTest.cpp:3321`)
  // 0-byte message: `otcrypto_rsa_sign` and `otcrypto_rsa_verify` with
  // `kOtcryptoRsaPaddingPkcs` + `kOtcryptoHashModeNull` and `len = 0` should
  // succeed (`OTCRYPTO_OK`; currently fails in `digest_check` at
  // `rsa_signature.c:45` and `digest_info_length_get` at `rsa_padding.c:35`).
  TRY(construct_rsa2048_keypair(kOtcryptoKeyModeRsaSignPkcs, pub_data,
                                &public_key, priv_blob, &private_key));
  uint32_t dummy_word = 0;
  otcrypto_hash_digest_t empty_raw_digest = {
      .mode = kOtcryptoHashModeNull,
      .data = &dummy_word,
      .len = 0,
  };
  TRY(otcrypto_rsa_sign(&private_key, empty_raw_digest, kOtcryptoRsaPaddingPkcs,
                        &sig_buf));
  hardened_bool_t verif_ok = kHardenedBoolFalse;
  TRY(otcrypto_rsa_verify(&public_key, empty_raw_digest,
                          kOtcryptoRsaPaddingPkcs, &const_sig_buf, &verif_ok));
  TRY_CHECK(verif_ok == kHardenedBoolTrue);

  return OK_STATUS();
}

OTTF_DEFINE_TEST_CONFIG();

bool test_main(void) {
  status_t result = OK_STATUS();
  otcrypto_state_t state = {0};
  CHECK_STATUS_OK(otcrypto_init(kOtcryptoKeySecurityLevelLow, &state));

  EXECUTE_TEST(result, rsa_vts_signing_no_digest_and_raw_test);
  EXECUTE_TEST(result, rsa_vts_signing_pkcs1_and_pss_hashes_test);
  EXECUTE_TEST(result, rsa_vts_encryption_modes_test);
  EXECUTE_TEST(result, rsa_vts_cts_empty_plaintext_and_no_digest_test);
  EXECUTE_TEST(result, rsa_vts_signing_zero_length_no_digest_test);

  return status_ok(result);
}
