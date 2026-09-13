// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/cert/dice_chain.h"

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/crypto/drivers/entropy.h"
#include "sw/device/silicon_creator/lib/base/boot_measurements.h"
#include "sw/device/silicon_creator/lib/base/sec_mmio.h"
#include "sw/device/silicon_creator/lib/base/static_dice_cdi_0.h"
#include "sw/device/silicon_creator/lib/base/util.h"
#include "sw/device/silicon_creator/lib/cert/dice.h"
#include "sw/device/silicon_creator/lib/dbg_print.h"
#include "sw/device/silicon_creator/lib/drivers/kmac.h"
#include "sw/device/silicon_creator/lib/drivers/otbn.h"
#include "sw/device/silicon_creator/lib/drivers/rnd.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/manifest.h"
#include "sw/device/silicon_creator/lib/nvm_ctrl.h"
#include "sw/device/silicon_creator/lib/otbn_boot_services.h"
#include "sw/device/silicon_creator/lib/ownership/datatypes.h"
#include "sw/device/silicon_creator/manuf/base/perso_tlv_data.h"

// Declare the OTBN application and symbols for the HMAC-based DICE app.
OTBN_DECLARE_APP_SYMBOLS(dice_chain_app);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, mode);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, wfi_enable);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, status);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, uds_s0);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, uds_s1);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, rom_ext_kdf_s0);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, rom_ext_kdf_s1);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, bl0_kdf_s0);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, bl0_kdf_s1);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, nonce);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, cdi0_s0);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, cdi0_s1);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, cdi1_s0);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, cdi1_s1);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, wrapped_key);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, d0);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, d1);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, x);
OTBN_DECLARE_SYMBOL_ADDR(dice_chain_app, y);

static const sc_otbn_app_t kOtbnAppDiceChainApp =
    OTBN_APP_T_INIT(dice_chain_app);

/**
 * Defines a class for parsing and building the DICE cert chain.
 *
 * All of the fields in this struct should be considered private, and users
 * should call the public `dice_chain_*` functions instead.
 */
typedef struct dice_chain {
  /**
   * RAM buffer that mirrors the DICE cert chain in a flash page.
   */
  dice_page_t page;

  /**
   * Indicate whether `page` needs to be written back to flash.
   */
  hardened_bool_t data_dirty;

  /**
   * The amount of bytes in `page.data` that has been processed.
   */
  size_t tail_offset;

  /**
   * Indicate the info page currently buffered in `page`.
   * This is used to skip unnecessary read ops.
   */
  nvm_info_page_t info_page;

  /**
   * Id pair which points to the endorsement and cert ids below.
   */
  cert_key_id_pair_t key_ids;

  /**
   * Public key id for signing endorsement cert.
   */
  hmac_digest_t endorsement_pubkey_id;

  /**
   * Subject public key id of the current cert.
   */
  hmac_digest_t subject_pubkey_id;

  /**
   * Subject public key contents of the current cert.
   */
  ecdsa_p256_public_key_t subject_pubkey;

  /**
   * Scratch buffer for constructing CDI certs.
   */
  uint8_t scratch_cert[kDicePageDataSize];

  /**
   * The current tlv cert the builder is processing.
   */
  perso_tlv_cert_obj_t cert_obj;

  /**
   * The version of the perso blob.
   */
  perso_blob_version_t blob_version;

  /**
   * Indicate whether the `cert_obj` is valid for the current `subject_pubkey`.
   */
  hardened_bool_t cert_valid;

} dice_chain_t;

static dice_chain_t dice_chain;

cert_key_id_pair_t dice_chain_cdi_0_key_ids = (cert_key_id_pair_t){
    .endorsement = &static_dice_cdi_0.uds_pubkey_id,
    .cert = &static_dice_cdi_0.cdi_0_pubkey_id,
};

// Get the size of the remaining tail space that is not processed yet.
OT_WARN_UNUSED_RESULT
OT_NOINLINE
static size_t dice_chain_get_tail_size(void) {
  HARDENED_CHECK_GE(sizeof(dice_chain.page.data), dice_chain.tail_offset);
  return sizeof(dice_chain.page.data) - dice_chain.tail_offset;
}

// Get the pointer to the remaining tail space that is not processed yet.
OT_WARN_UNUSED_RESULT
static uint8_t *dice_chain_get_tail_buffer(void) {
  return &dice_chain.page.data[dice_chain.tail_offset];
}

// Cleanup stale `cert_obj` data and mark it as invalid.
static void dice_chain_reset_cert_obj(void) {
  memset(&dice_chain.cert_obj, 0, sizeof(dice_chain.cert_obj));
  dice_chain.cert_valid = kHardenedBoolFalse;
}

/**
 * Increments the DICE cert buffer offset to the next TLV object.
 * (ensuring to round up to the 64-bit flash word offset to prevent potential
 * ECC issues).
 */
static void dice_chain_next_cert_obj(void) {
  // Round up to next flash word for next perso TLV object offset.
  size_t cert_size = dice_chain.cert_obj.obj_size;

  // The cert_size is only 12-bit, which won't cause unsigned overflow.
  cert_size = util_size_to_words(cert_size) * sizeof(uint32_t);
  cert_size = util_round_up_to(cert_size, 3);

  // Jump to the next object.
  dice_chain.tail_offset += cert_size;

  // Post-check for the buffer boundary.
  HARDENED_CHECK_LE(dice_chain.tail_offset, sizeof(dice_chain.page.data));

  dice_chain_reset_cert_obj();
}

/**
 * Load the tlv cert obj from the tail buffer and check if it's valid.
 *
 * This method will update the `dice_chain` fields of current certificate:
 *   * `cert_obj` will be all zeros if not TLV cert entry is found.
 *   * `cert_valid` will only be set to true if name and pubkey matches.
 *
 * @param name The cert name to match.
 * @param name_size Size in byte of the `name` argument. Caller has to ensure it
 * is smaller than kCrthNameSizeFieldMask.
 * @return errors encountered during the operation.
 */
OT_WARN_UNUSED_RESULT
static rom_error_t dice_chain_load_cert_obj(const char *name,
                                            size_t name_size) {
  rom_error_t err = perso_tlv_get_cert_obj(
      dice_chain_get_tail_buffer(), dice_chain_get_tail_size(),
      dice_chain.blob_version, &dice_chain.cert_obj);
  if (err != kErrorOk) {
    // Cleanup the stale value if error.
    dice_chain_reset_cert_obj();

    // If the cert is not found or corrupted, continue and allow the ROM_EXT
    // to generate an identity certificate for the current DICE stage. The
    // error is not fatal, and the cert obj has been marked as invalid.
    return kErrorOk;
  }

  // Check if this cert is what we are looking for. The name and type (X.509 vs
  // CWT) should match.
  const perso_tlv_object_type_t kExpectedCertType =
      kDiceCertFormat == kDiceCertFormatX509TcbInfo ? kPersoObjectTypeX509Cert
                                                    : kPersoObjectTypeCwtCert;
  if (name == NULL || memcmp(dice_chain.cert_obj.name, name, name_size) != 0 ||
      kExpectedCertType != dice_chain.cert_obj.obj_type) {
    // Name unmatched, keep the cert_obj but mark it as invalid.
    dice_chain.cert_valid = kHardenedBoolFalse;
    return kErrorOk;
  }

  // Check if the subject pubkey is matched. `cert_valid` will be set to false
  // if unmatched.
  RETURN_IF_ERROR(dice_cert_check_valid(
      &dice_chain.cert_obj, &dice_chain.subject_pubkey_id,
      &dice_chain.subject_pubkey, &dice_chain.cert_valid));

  return kErrorOk;
}

// Skip the TLV entry if the name matches.
static rom_error_t dice_chain_skip_cert_obj(const char *name,
                                            size_t name_size) {
  RETURN_IF_ERROR(dice_chain_load_cert_obj(NULL, 0));
  if (memcmp(dice_chain.cert_obj.name, name, name_size) == 0) {
    dice_chain_next_cert_obj();
  }
  return kErrorOk;
}

// Load the certificate data from flash to RAM buffer.
OT_WARN_UNUSED_RESULT
static rom_error_t dice_chain_load_nvm(nvm_info_page_t info_page) {
  // Skip reload if it's already buffered.
  if (dice_chain.info_page == info_page) {
    dice_chain.tail_offset = 0;
    return kErrorOk;
  }

  // We are switching to a different page, flush changes (if dirty) first.
  RETURN_IF_ERROR(dice_chain_flush_nvm());

  // Read in a DICE certificate(s) page.
  RETURN_IF_ERROR(nvm_ctrl_info_read_zeros_on_read_error(
      info_page, /*offset=*/0,
      /*word_count=*/kDicePageWords, &dice_chain.page));

  // Resets the flash page status.
  dice_chain.data_dirty = kHardenedBoolFalse;
  dice_chain.tail_offset = 0;
  dice_chain.info_page = info_page;
  dice_chain_reset_cert_obj();

  // Detect the version of the blob stored in flash.
  size_t offset = 0;
  RETURN_IF_ERROR(perso_tlv_get_blob_version(
      dice_chain.page.data, sizeof(dice_chain.page.data),
      &dice_chain.blob_version, &offset));
  dice_chain.tail_offset = util_round_up_to(offset, 3);

  return kErrorOk;
}

// Add the hash digest to the last of the page.
static rom_error_t dice_chain_seal_page(void) {
  // Hash the entire page before the digest.
  hmac_sha256(dice_chain.page.data, sizeof(dice_chain.page.data),
              &dice_chain.page.digest);

  // The page is going to be updated.
  dice_chain.data_dirty = kHardenedBoolTrue;

  return kErrorOk;
}

// Push the certificate to the tail with TLV header.
OT_WARN_UNUSED_RESULT
static rom_error_t dice_chain_push_cert(const char *name, const uint8_t *cert,
                                        const size_t cert_size) {
  // The data is going to be updated, mark it as dirty and clear the tail.
  dice_chain.data_dirty = kHardenedBoolTrue;

  // Invalidate all the remaining certificates in the tail buffer.
  memset(dice_chain_get_tail_buffer(), 0, dice_chain_get_tail_size());

  // Encode the certificate to the tail buffer.
  size_t cert_page_left = dice_chain_get_tail_size();
  perso_tlv_object_type_t cert_type =
      kDiceCertFormat == kDiceCertFormatX509TcbInfo ? kPersoObjectTypeX509Cert
                                                    : kPersoObjectTypeCwtCert;
  RETURN_IF_ERROR(perso_tlv_cert_obj_build(
      name, cert_type, cert, cert_size, dice_chain.blob_version,
      dice_chain_get_tail_buffer(), &cert_page_left));

  // Move the offset to the new tail.
  RETURN_IF_ERROR(perso_tlv_get_cert_obj(
      dice_chain_get_tail_buffer(), dice_chain_get_tail_size(),
      dice_chain.blob_version, &dice_chain.cert_obj));
  dice_chain_next_cert_obj();
  return kErrorOk;
}

rom_error_t dice_chain_attestation_silicon(void) {
  // Initialize the entropy complex and KMAC for key manager operations.
  // Note: `OTCRYPTO_OK.value` is equal to `kErrorOk` but we cannot add a static
  // assertion here since its definition is not an integer constant expression.
  HARDENED_RETURN_IF_ERROR(
      (rom_error_t)entropy_complex_init(kHardenedBoolFalse).value);
  HARDENED_RETURN_IF_ERROR(kmac_keymgr_configure());

  // Set keymgr reseed interval. Start with the maximum value to avoid
  // entropy complex contention during the boot process.
  const uint16_t kScKeymgrEntropyReseedInterval = UINT16_MAX;
  sc_keymgr_entropy_reseed_interval_set(kScKeymgrEntropyReseedInterval);
  SEC_MMIO_WRITE_INCREMENT(kScKeymgrSecMmioEntropyReseedIntervalSet);

  // ROM sets the SW binding values for the first key stage (CreatorRootKey) but
  // does not initialize the key manager. Advance key manager state twice to
  // transition to the CreatorRootKey state.
  RETURN_IF_ERROR(sc_keymgr_state_check(kScKeymgrStateReset));
  sc_keymgr_advance_state();
  RETURN_IF_ERROR(sc_keymgr_state_check(kScKeymgrStateInit));

  // Generate UDS keys.
  sc_keymgr_advance_state();
  HARDENED_RETURN_IF_ERROR(sc_keymgr_state_check(kScKeymgrStateCreatorRootKey));
  HARDENED_RETURN_IF_ERROR(otbn_boot_cert_ecc_p256_keygen(
      kDiceKeyUds, &static_dice_cdi_0.uds_pubkey_id,
      &static_dice_cdi_0.uds_pubkey));

  // Save UDS key for signing next stage cert.
  RETURN_IF_ERROR(otbn_boot_attestation_key_save(
      kDiceKeyUds.keygen_seed_idx, kDiceKeyUds.type,
      *kDiceKeyUds.keymgr_diversifier));

  return kErrorOk;
}

/**
 * Formats a 64-byte Block 1 for NIST SP 800-108 KDF in Counter Mode:
 *   Message = [1]_2 || "CDI_Attest" || 0x00 || Measurement[32] || [256]_2
 * Followed by SHA-256 padding on 115 bytes (64 key + 51 message):
 *   Padding = 0x80 || 0x00000000 || 0x0000000000000398 (920 bits)
 */
static void dice_kdf_sp800_108_format(const uint8_t *measurement,
                                      uint32_t *out_words) {
  uint8_t *raw = (uint8_t *)out_words;
  memset(raw, 0, 64);
  // [1]_2 = 0x00000001 (4 bytes big-endian)
  raw[0] = 0x00;
  raw[1] = 0x00;
  raw[2] = 0x00;
  raw[3] = 0x01;
  // Label = "CDI_Attest" (10 bytes)
  memcpy(&raw[4], "CDI_Attest", 10);
  // Separator byte = 0x00 (byte 14, already 0)
  // Context = 32-byte measurement
  memcpy(&raw[15], measurement, 32);
  // [L]_2 = 256 = 0x00000100 (4 bytes big-endian)
  raw[47] = 0x00;
  raw[48] = 0x00;
  raw[49] = 0x01;
  raw[50] = 0x00;
  // SHA-256 padding delimiter
  raw[51] = 0x80;
  // Bit length: 920 bits = 0x0398 (bytes 56..63)
  raw[62] = 0x03;
  raw[63] = 0x98;
}

rom_error_t dice_chain_attestation_creator(
    keymgr_binding_value_t *rom_ext_measurement,
    const manifest_t *rom_ext_manifest) {
  // 1. Load the DICE chain OTBN application.
  HARDENED_RETURN_IF_ERROR(sc_otbn_load_app(kOtbnAppDiceChainApp));

  // 2. Prepare parameters: mode = 1 (MODE_CREATOR_STAGE), wfi_enable = 1.
  uint32_t mode = 1;
  uint32_t wfi_en = 1;
  HARDENED_RETURN_IF_ERROR(
      sc_otbn_dmem_write(1, &mode, OTBN_ADDR_T_INIT(dice_chain_app, mode)));
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(
      1, &wfi_en, OTBN_ADDR_T_INIT(dice_chain_app, wfi_enable)));

  // Zero UDS in DMEM so OTBN pulls it from sideloaded WSRs KEY_S0_L / KEY_S1_L.
  uint32_t zero_buf[8] = {0};
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(
      8, zero_buf, OTBN_ADDR_T_INIT(dice_chain_app, uds_s0)));
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(
      8, zero_buf, OTBN_ADDR_T_INIT(dice_chain_app, uds_s1)));

  // Prepare 2-share SP 800-108 KDF message blocks for rom_ext and bl0 (64 bytes
  // each).
  uint32_t rom_ext_kdf_s0[16];
  uint32_t rom_ext_kdf_s1[16];
  uint32_t bl0_kdf_s0[16];
  uint32_t bl0_kdf_s1[16];
  uint32_t nonce_buf[8];

  dice_kdf_sp800_108_format((const uint8_t *)rom_ext_measurement->data,
                            rom_ext_kdf_s0);
  dice_kdf_sp800_108_format((const uint8_t *)boot_measurements.bl0.data,
                            bl0_kdf_s0);

  for (size_t i = 0; i < 16; ++i) {
    uint32_t mask = rnd_uint32();
    rom_ext_kdf_s1[i] = mask;
    rom_ext_kdf_s0[i] ^= mask;

    mask = rnd_uint32();
    bl0_kdf_s1[i] = mask;
    bl0_kdf_s0[i] ^= mask;
  }

  for (size_t i = 0; i < 8; ++i) {
    nonce_buf[i] = rnd_uint32();
  }

  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(
      16, rom_ext_kdf_s0, OTBN_ADDR_T_INIT(dice_chain_app, rom_ext_kdf_s0)));
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(
      16, rom_ext_kdf_s1, OTBN_ADDR_T_INIT(dice_chain_app, rom_ext_kdf_s1)));
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(
      16, bl0_kdf_s0, OTBN_ADDR_T_INIT(dice_chain_app, bl0_kdf_s0)));
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(
      16, bl0_kdf_s1, OTBN_ADDR_T_INIT(dice_chain_app, bl0_kdf_s1)));
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(
      8, nonce_buf, OTBN_ADDR_T_INIT(dice_chain_app, nonce)));

  // 3. Sideload UDS to OTBN.
  HARDENED_RETURN_IF_ERROR(sc_keymgr_state_check(kScKeymgrStateCreatorRootKey));
  HARDENED_RETURN_IF_ERROR(sc_keymgr_generate_key_otbn(
      kDiceKeyUds.type, *kDiceKeyUds.keymgr_diversifier));

  // 4. Enable OTBN WFI and start execution.
  sc_otbn_wfi_enable();
  SEC_MMIO_WRITE_INCREMENT(kScOtbnSecMmioExecute);
  HARDENED_RETURN_IF_ERROR(sc_otbn_execute_start());

  // 5. Wait for OTBN to pause at WFI.
  HARDENED_RETURN_IF_ERROR(sc_otbn_wait_for_pause());

  // 6. While OTBN is paused, advance Keymgr to Owner stage.
  keymgr_binding_value_t seal_binding_value = {
      .data = {rom_ext_manifest->identifier, 0}};
  SEC_MMIO_WRITE_INCREMENT(kScKeymgrSecMmioSwBindingSet +
                           kScKeymgrSecMmioOwnerIntMaxVerSet);
  HARDENED_RETURN_IF_ERROR(sc_keymgr_owner_int_advance(
      /*sealing_binding=*/&seal_binding_value,
      /*attest_binding=*/rom_ext_measurement,
      rom_ext_manifest->max_key_version));
  sc_keymgr_sw_binding_unlock_wait();

  keymgr_binding_value_t owner_seal_binding = {
      .data = {rom_ext_manifest->identifier, 0}};
  SEC_MMIO_WRITE_INCREMENT(kScKeymgrSecMmioSwBindingSet +
                           kScKeymgrSecMmioOwnerMaxVerSet);
  HARDENED_RETURN_IF_ERROR(sc_keymgr_owner_advance(
      /*sealing_binding=*/&owner_seal_binding,
      /*attest_binding=*/&boot_measurements.bl0,
      rom_ext_manifest->max_key_version));
  sc_keymgr_sw_binding_unlock_wait();

  // 7. Sideload Owner key to KMAC and configure KMAC.
  HARDENED_RETURN_IF_ERROR(sc_keymgr_generate_key(
      kScKeymgrDestKmac, kDiceKeyCdi1.type, *kDiceKeyCdi1.keymgr_diversifier));
  HARDENED_RETURN_IF_ERROR(kmac_kmac256_hw_configure());

  // 8. Resume OTBN to wrap CDI_1.
  sc_otbn_wfi_resume();

  // 9. Wait for OTBN completion and check status.
  HARDENED_RETURN_IF_ERROR(sc_otbn_busy_wait_for_done());
  uint32_t otbn_status = UINT32_MAX;
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_read(
      1, OTBN_ADDR_T_INIT(dice_chain_app, status), &otbn_status));
  HARDENED_CHECK_EQ(otbn_status, 0);

  // 10. Read CDI_0 public key (x, y) from OTBN.
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_read(
      kEcdsaP256PublicKeyCoordWords, OTBN_ADDR_T_INIT(dice_chain_app, x),
      static_dice_cdi_0.cdi_0_pubkey.x));
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_read(
      kEcdsaP256PublicKeyCoordWords, OTBN_ADDR_T_INIT(dice_chain_app, y),
      static_dice_cdi_0.cdi_0_pubkey.y));

  // Convert public key from LE to BE and compute pubkey_id.
  util_reverse_bytes(static_dice_cdi_0.cdi_0_pubkey.x,
                     kEcdsaP256PublicKeyCoordBytes);
  util_reverse_bytes(static_dice_cdi_0.cdi_0_pubkey.y,
                     kEcdsaP256PublicKeyCoordBytes);
  hmac_sha256(&static_dice_cdi_0.cdi_0_pubkey,
              sizeof(static_dice_cdi_0.cdi_0_pubkey),
              &static_dice_cdi_0.cdi_0_pubkey_id);
  util_reverse_bytes(&static_dice_cdi_0.cdi_0_pubkey_id,
                     sizeof(static_dice_cdi_0.cdi_0_pubkey_id));

  // 11. Read wrapped CDI_1 envelope (96 bytes) from OTBN.
  uint8_t wrapped_key_buf[kDiceWrappedKeySize];
  HARDENED_RETURN_IF_ERROR(
      sc_otbn_dmem_read(kDiceWrappedKeySize / sizeof(uint32_t),
                        OTBN_ADDR_T_INIT(dice_chain_app, wrapped_key),
                        (uint32_t *)wrapped_key_buf));

  // 12. Switch page for the device generated certificates.
  RETURN_IF_ERROR(dice_chain_load_nvm(kNvmInfoPageDiceCerts));

  // Check if current CDI_0 cert is valid.
  dice_chain.subject_pubkey_id = static_dice_cdi_0.cdi_0_pubkey_id;
  dice_chain.subject_pubkey = static_dice_cdi_0.cdi_0_pubkey;
  RETURN_IF_ERROR(dice_chain_load_cert_obj("CDI_0", /*name_size=*/6));
  if (dice_chain.cert_valid == kHardenedBoolFalse) {
    static_dice_cdi_0.cert_size = sizeof(static_dice_cdi_0.cert_data);
    HARDENED_RETURN_IF_ERROR(dice_cdi_0_cert_build(
        (hmac_digest_t *)rom_ext_measurement->data,
        rom_ext_manifest->security_version, &dice_chain_cdi_0_key_ids,
        &static_dice_cdi_0.uds_pubkey, &static_dice_cdi_0.cdi_0_pubkey,
        static_dice_cdi_0.cert_data, &static_dice_cdi_0.cert_size));
    RETURN_IF_ERROR(dice_chain_push_cert("CDI_0", static_dice_cdi_0.cert_data,
                                         static_dice_cdi_0.cert_size));
  } else {
    dice_chain_next_cert_obj();
  }

  // Push WRAPPED_CDI_1 to flash page buffer.
  RETURN_IF_ERROR(dice_chain_push_cert("WRAPPED_CDI_1", wrapped_key_buf,
                                       kDiceWrappedKeySize));

  return kErrorOk;
}

// Compare the UDS identity in the static critical section to the UDS cert
// cached in the flash.
static rom_error_t dice_chain_attestation_check_uds(void) {
  // Switch page for the factory provisioned UDS cert.
  RETURN_IF_ERROR(dice_chain_load_nvm(kNvmInfoPageFactoryCerts));

  // Check if the UDS cert is valid.
  dice_chain.endorsement_pubkey_id = static_dice_cdi_0.uds_pubkey_id;
  dice_chain.subject_pubkey_id = static_dice_cdi_0.uds_pubkey_id;
  dice_chain.subject_pubkey = static_dice_cdi_0.uds_pubkey;
  RETURN_IF_ERROR(dice_chain_load_cert_obj("UDS", /*name_size=*/4));
  if (dice_chain.cert_valid == kHardenedBoolFalse) {
    // The UDS key ID (and cert itself) should never change unless:
    // 1. there is a hardware issue / the page has been corrupted, or
    // 2. the cert has not yet been provisioned.
    //
    // In both cases, we do nothing, and boot normally, later attestation
    // attempts will fail in a detectable manner.

    // CAUTION: This error message should match the one in
    //   //sw/host/provisioning/ft_lib/src/lib.rs
    dbg_puts("error: UDS certificate not valid\r\n");
  }

  return kErrorOk;
}

// Refresh the cache if a new CDI_0 is generated.
static rom_error_t dice_chain_attestation_check_cdi_0(void) {
  // Switch page for the device CDI chain.
  RETURN_IF_ERROR(dice_chain_load_nvm(kNvmInfoPageDiceCerts));

  // Set the endorsement key for the next cert.
  dice_chain.endorsement_pubkey_id = static_dice_cdi_0.cdi_0_pubkey_id;

  // Save cdi 0 to flash if regenerated.
  if (static_dice_cdi_0.cert_size != 0) {
    dbg_puts("warning: CDI_0 certificate not valid; updating\r\n");
    RETURN_IF_ERROR(dice_chain_push_cert("CDI_0", static_dice_cdi_0.cert_data,
                                         static_dice_cdi_0.cert_size));
  } else {
    RETURN_IF_ERROR(dice_chain_skip_cert_obj("CDI_0", /*name_size=*/6));
  }

  // Skip WRAPPED_CDI_1 object so tail_offset points to CDI_1.
  RETURN_IF_ERROR(dice_chain_skip_cert_obj("WRAPPED_CDI_1", /*name_size=*/13));

  return kErrorOk;
}

// Check the hash digest at the last of the page.
static rom_error_t dice_chain_seal_page_check(nvm_info_page_t info_page) {
  RETURN_IF_ERROR(dice_chain_load_nvm(info_page));
  // Hash the entire page before the digest.
  hmac_digest_t expected_digest;
  hmac_sha256(dice_chain.page.data, sizeof(dice_chain.page.data),
              &expected_digest);

  // Compare with the digest stored at the end of the page.
  if (memcmp(&dice_chain.page.digest, &expected_digest,
             sizeof(hmac_digest_t)) != 0) {
    return kErrorDicePageCorrupted;
  }

  return kErrorOk;
}

rom_error_t dice_chain_rom_ext_check(void) {
  if (dice_chain_seal_page_check(kNvmInfoPageFactoryCerts) != kErrorOk) {
    dbg_puts("warning: corrupted FactoryCerts page\r\n");
  }

  // Retry if the current cache is corrupted.
  rom_error_t error = dice_chain_seal_page_check(kNvmInfoPageDiceCerts);
  if (error == kErrorDicePageCorrupted) {
    dbg_puts("warning: corrupted DiceCerts page\r\n");
    // Clear the corrupted page and reboot.
    dice_chain.data_dirty = kHardenedBoolTrue;
    memset(&dice_chain.page, 0, sizeof(dice_chain.page));
    RETURN_IF_ERROR(dice_chain_flush_nvm());

    if (static_dice_cdi_0.cert_size > 0) {
      // Continue since CDI_0 has been generated
      error = kErrorOk;
    }
  }
  RETURN_IF_ERROR(error);

  // Handles the certificates from the immutable rom_ext.
  RETURN_IF_ERROR(dice_chain_attestation_check_uds());
  RETURN_IF_ERROR(dice_chain_attestation_check_cdi_0());

  return kErrorOk;
}

rom_error_t dice_chain_attestation_owner(
    const manifest_t *owner_manifest, keymgr_binding_value_t *bl0_measurement,
    hmac_digest_t *owner_measurement, hmac_digest_t *owner_history_hash,
    keymgr_binding_value_t *sealing_binding, owner_app_domain_t key_domain) {
  // Generate CDI_1 attestation keys and (potentially) update certificate.
  SEC_MMIO_WRITE_INCREMENT(kScKeymgrSecMmioSwBindingSet +
                           kScKeymgrSecMmioOwnerIntMaxVerSet);
  static_assert(
      sizeof(hmac_digest_t) == sizeof(keymgr_binding_value_t),
      "Expect the keymgr binding value to be the same size as a sha256 digest");

  // Aggregate the owner firmware (BL0) measurement and the ownership
  // measurement into a single attestation measurment.  The attestation
  // measurement is used to initialize the keymgr.
  hmac_digest_t attest_measurement;
  hmac_sha256_configure(false);
  hmac_sha256_start();
  hmac_sha256_update(bl0_measurement, sizeof(*bl0_measurement));
  hmac_sha256_update(owner_measurement, sizeof(*owner_measurement));
  hmac_sha256_process();
  hmac_sha256_final(&attest_measurement);

  HARDENED_RETURN_IF_ERROR(sc_keymgr_owner_advance(
      /*sealing_binding=*/sealing_binding,
      /*attest_binding=*/(keymgr_binding_value_t *)&attest_measurement,
      owner_manifest->max_key_version));
  HARDENED_RETURN_IF_ERROR(otbn_boot_cert_ecc_p256_keygen(
      kDiceKeyCdi1, &dice_chain.subject_pubkey_id, &dice_chain.subject_pubkey));

  // Check if the current CDI_1 cert is valid.
  RETURN_IF_ERROR(dice_chain_load_cert_obj("CDI_1", /*name_size=*/6));
  if (dice_chain.cert_valid == kHardenedBoolFalse) {
    dbg_puts("warning: CDI_1 certificate not valid; updating\r\n");
    // Update the cert page buffer.
    size_t updated_cert_size = kDicePageDataSize;
    // TODO(#19596): add owner configuration block measurement to CDI_1 cert.
    HARDENED_RETURN_IF_ERROR(dice_cdi_1_cert_build(
        (hmac_digest_t *)bl0_measurement, owner_measurement, owner_history_hash,
        owner_manifest->security_version, key_domain, &dice_chain.key_ids,
        &static_dice_cdi_0.cdi_0_pubkey, &dice_chain.subject_pubkey,
        dice_chain.scratch_cert, &updated_cert_size));
    RETURN_IF_ERROR(dice_chain_push_cert("CDI_1", dice_chain.scratch_cert,
                                         updated_cert_size));
  } else {
    // Cert is valid, move to the next one.
    dice_chain_next_cert_obj();

    // Replace CDI_0 with CDI_1 key for endorsing next stage cert.
    HARDENED_RETURN_IF_ERROR(otbn_boot_attestation_key_save(
        kDiceKeyCdi1.keygen_seed_idx, kDiceKeyCdi1.type,
        *kDiceKeyCdi1.keymgr_diversifier));
  }
  dice_chain.endorsement_pubkey_id = dice_chain.subject_pubkey_id;

  sc_keymgr_sw_binding_unlock_wait();

  return kErrorOk;
}

// Write the DICE certs to flash if they have been updated.
rom_error_t dice_chain_flush_nvm(void) {
  if (dice_chain.data_dirty == kHardenedBoolTrue) {
    RETURN_IF_ERROR(dice_chain_seal_page());

    // Error if a different page to kNvmInfoPageDiceCerts is provided.
    HARDENED_CHECK_EQ(dice_chain.info_page, kNvmInfoPageDiceCerts);
    static_assert(sizeof(dice_chain.page) == kNvmInfoPageDiceCertsSize,
                  "Invalid dice_chain buffer size");
    RETURN_IF_ERROR(nvm_ctrl_info_erase(dice_chain.info_page));
    RETURN_IF_ERROR(nvm_ctrl_info_write(dice_chain.info_page,
                                        /*offset=*/0,
                                        /*word_count=*/kDicePageWords,
                                        &dice_chain.page));
    dice_chain.data_dirty = kHardenedBoolFalse;
  }
  return kErrorOk;
}

rom_error_t dice_chain_init(void) {
  // Variable initialization.
  memset(&dice_chain, 0, sizeof(dice_chain));
  dice_chain.data_dirty = kHardenedBoolFalse;
  dice_chain.key_ids = (cert_key_id_pair_t){
      .endorsement = &dice_chain.endorsement_pubkey_id,
      .cert = &dice_chain.subject_pubkey_id,
  };
  dice_chain_reset_cert_obj();

  // Configure DICE certificate flash info page and buffer it into RAM.
  nvm_ctrl_cert_info_page_creator_cfg(kNvmInfoPageDiceCerts);
  nvm_ctrl_info_cfg_set(kNvmInfoPageFactoryCerts, kNvmCertInfoPageCfg);
  nvm_ctrl_cert_info_page_owner_restrict(kNvmInfoPageFactoryCerts);
  return kErrorOk;
}

rom_error_t dice_chain_get_wrapped_cdi1(uint8_t *wrapped_key, size_t *len) {
  if (wrapped_key == NULL || len == NULL || *len < kDiceWrappedKeySize) {
    return kErrorDiceInternal;
  }
  RETURN_IF_ERROR(dice_chain_load_nvm(kNvmInfoPageDiceCerts));

  uint8_t *buf = dice_chain.page.data;
  size_t offset = 0;
  perso_blob_version_t blob_version;
  RETURN_IF_ERROR(perso_tlv_get_blob_version(dice_chain.page.data,
                                             sizeof(dice_chain.page.data),
                                             &blob_version, &offset));
  offset = util_round_up_to(offset, 3);

  while (offset < sizeof(dice_chain.page.data)) {
    perso_tlv_cert_obj_t obj;
    rom_error_t err = perso_tlv_get_cert_obj(
        &buf[offset], sizeof(dice_chain.page.data) - offset, blob_version,
        &obj);
    if (err != kErrorOk) {
      break;
    }
    if (memcmp(obj.name, "WRAPPED_CDI_1", 13) == 0) {
      if (obj.cert_body_size < kDiceWrappedKeySize) {
        return kErrorDiceInternal;
      }
      memcpy(wrapped_key, obj.cert_body_p, kDiceWrappedKeySize);
      *len = kDiceWrappedKeySize;
      return kErrorOk;
    }
    size_t obj_size = util_size_to_words(obj.obj_size) * sizeof(uint32_t);
    obj_size = util_round_up_to(obj_size, 3);
    if (obj_size == 0) {
      break;
    }
    offset += obj_size;
  }
  return kErrorPersoTlvCertObjNotFound;
}
