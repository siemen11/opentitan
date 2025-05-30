// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_OWNERSHIP_DATATYPES_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_OWNERSHIP_DATATYPES_H_

#include <stdint.h>

#include "sw/device/lib/base/bitfield.h"
#include "sw/device/lib/base/macros.h"
#include "sw/device/silicon_creator/lib/sigverify/ecdsa_p256_key.h"
#include "sw/device/silicon_creator/lib/sigverify/rsa_key.h"
#include "sw/device/silicon_creator/lib/sigverify/spx_key.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef struct hybrid_key {
  ecdsa_p256_public_key_t ecdsa;
  sigverify_spx_key_t spx;
} hybrid_key_t;

/**
 * An owner_key can be either a ECDSA P256 or SPX+ key.  The type of the key
 * material will be determined by a separate field on the owner block
 */
typedef union owner_key {
  /** ECDSA P256 public key */
  ecdsa_p256_public_key_t ecdsa;
  /** SPHINCS+ public key */
  sigverify_spx_key_t spx;
  /** Hybrid ECDSA & SPHINCS+ public key */
  hybrid_key_t hybrid;
  /** Enough space to hold an ECDSA key and a SPX+ key for hybrid schemes */
  uint32_t raw[16 + 8];
} owner_key_t;

/**
 * An owner_signature is an ECDSA P256 signature.
 */
typedef union owner_signature {
  /** ECDSA P256 signature key */
  ecdsa_p256_signature_t ecdsa;
  uint32_t raw[16];
} owner_signature_t;

typedef enum ownership_state {
  /* Locked Owner: `OWND`. */
  kOwnershipStateLockedOwner = 0x444e574f,
  /* Locked Update: `USLF`. */
  kOwnershipStateUnlockedSelf = 0x464c5355,
  /* Unlocked Any: `UANY`. */
  kOwnershipStateUnlockedAny = 0x594e4155,
  /* Unlocked Endorsed: `UEND`. */
  kOwnershipStateUnlockedEndorsed = 0x444e4555,
  /* Locked None: any bit pattern not listed above. */
  kOwnershipStateRecovery = 0,
} ownership_state_t;

typedef enum ownership_key_alg {
  /** Key algorithm RSA: `RSA3` */
  kOwnershipKeyAlgRsa = 0x33415352,
  /** Key algorithm ECDSA P-256: `P256` */
  kOwnershipKeyAlgEcdsaP256 = 0x36353250,
  /** Key algorithm SPX+ Pure: `S+Pu` */
  kOwnershipKeyAlgSpxPure = 0x75502b53,
  /** Key algorithm SPX+ Prehashed SHA256: `S+S2` */
  kOwnershipKeyAlgSpxPrehash = 0x32532b53,
  /** Key algorithm Hybrid P256 & SPX+ Pure: `H+Pu` */
  kOwnershipKeyAlgHybridSpxPure = 0x75502b48,
  /** Key algorithm Hybrid P256 & SPX+ Prehashed SHA256: `H+S2` */
  kOwnershipKeyAlgHybridSpxPrehash = 0x32532b48,

  // Tentative identifiers for SPHINCS+ q20 variants (not yet supported):
  // Key algorithm SPX+ Pure: `SqPu`
  kOwnershipKeyAlgSq20Pure = 0x75507153,
  // Key algorithm SPX+ Prehashed SHA256: `SqS2`
  kOwnershipKeyAlgSq20Prehash = 0x32537153,
  // Key algorithm Hybrid P256 & SPX+ Pure: `HqPu`
  kOwnershipKeyAlgHybridSq20Pure = 0x75507148,
  // Key algorithm Hybrid P256 & SPX+ Prehashed SHA256: `HqS2`
  kOwnershipKeyAlgHybridSq20Prehash = 0x32537148,

  /** Key algorithm category mask */
  kOwnershipKeyAlgCategoryMask = 0xFF,
  /** Key algorithm category for Sphincs+: `S...` */
  kOwnershipKeyAlgCategorySpx = 0x53,
  /** Key algorithm category for Hybrid: `H...` */
  kOwnershipKeyAlgCategoryHybrid = 0x48,
} ownership_key_alg_t;

typedef enum ownership_update_mode {
  /** Update mode open: `OPEN` (unlock key has full power) */
  kOwnershipUpdateModeOpen = 0x4e45504f,
  /** Update mode self: `SELF` (unlock key only unlocks to UnlockedSelf) */
  kOwnershipUpdateModeSelf = 0x464c4553,
  /**
   * Update mode NewVersion: `NEWV`
   * (unlock key can't unlock; accept new owner configs from self-same owner
   * if the config_version is newer)
   */
  kOwnershipUpdateModeNewVersion = 0x5657454e,
  /**
   * Update mode SelfVersion: `SELV`
   * (unlock key only unlocks to UnlockedSelf; accept new owner configs from
   * self-same owner if the config_version is newer)
   */
  kOwnershipUpdateModeSelfVersion = 0x564c4553,
} ownership_update_mode_t;

typedef enum lock_constraint {
  /** No locking constraint: `~~~~`. */
  kLockConstraintNone = 0x7e7e7e7e,
} lock_constraint_t;

typedef enum tlv_tag {
  /** Owner struct: `OWNR`. */
  kTlvTagOwner = 0x524e574f,
  /** Application Key: `APPK`. */
  kTlvTagApplicationKey = 0x4b505041,
  /** Flash Configuration: `FLSH`. */
  kTlvTagFlashConfig = 0x48534c46,
  /** Flash INFO configuration: `INFO`. */
  kTlvTagInfoConfig = 0x4f464e49,
  /** Rescue Configuration: `RESQ`. */
  kTlvTagRescueConfig = 0x51534552,
  /** Not Present: `ZZZZ`. */
  kTlvTagNotPresent = 0x5a5a5a5a,
} tlv_tag_t;

typedef struct struct_version {
  uint8_t major;
  uint8_t minor;
} struct_version_t;

typedef struct tlv_header {
  uint32_t tag;
  uint16_t length;
  struct_version_t version;
} tlv_header_t;

typedef enum owner_sram_exec_mode {
  /** SRAM Exec disabled and locked: `LNEX`. */
  kOwnerSramExecModeDisabledLocked = 0x58454e4c,
  /** SRAM Exec disabled: `NOEX`. */
  kOwnerSramExecModeDisabled = 0x58454f4e,
  /** SRAM Exec enabled: `EXEC` */
  kOwnerSramExecModeEnabled = 0x43455845,
} owner_sram_exec_mode_t;

/**
 * The owner configuration block describes an owner identity and configuration.
 */
typedef struct owner_block {
  /**
   * Header identifying this struct.
   * tag: `OWNR`.
   * length: 2048.
   * version: 0
   */
  tlv_header_t header;
  /** Configuraion version (monotonically increasing per owner) */
  uint32_t config_version;
  /** SRAM execution configuration (DisabledLocked, Disabled, Enabled). */
  uint32_t sram_exec_mode;
  /** Ownership key algorithm (currently, only ECDSA is supported). */
  uint32_t ownership_key_alg;
  /** Ownership update mode (one of OPEN, SELF, NEWV) */
  uint32_t update_mode;
  /** Set the minimum security version to this value (UINT32_MAX: no change) */
  uint32_t min_security_version_bl0;
  /** The device ID locking constraint */
  uint32_t lock_constraint;
  /** The device ID to which this config applies */
  uint32_t device_id[8];
  /** Reserved space for future use. */
  uint32_t reserved[16];
  /** Owner public key. */
  owner_key_t owner_key;
  /** Owner's Activate public key. */
  owner_key_t activate_key;
  /** Owner's Unlock public key. */
  owner_key_t unlock_key;
  /** Data region to hold the other configuration structs. */
  uint8_t data[1536];
  /** Signature over the owner block with the Owner private key. */
  owner_signature_t signature;
  /** A sealing value to seal the owner block to a specific chip. */
  uint32_t seal[8];
} owner_block_t;

OT_ASSERT_MEMBER_OFFSET(owner_block_t, header, 0);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, config_version, 8);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, sram_exec_mode, 12);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, ownership_key_alg, 16);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, update_mode, 20);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, min_security_version_bl0, 24);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, lock_constraint, 28);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, device_id, 32);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, reserved, 64);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, owner_key, 128);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, activate_key, 224);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, unlock_key, 320);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, data, 416);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, signature, 1952);
OT_ASSERT_MEMBER_OFFSET(owner_block_t, seal, 2016);
OT_ASSERT_SIZE(owner_block_t, 2048);

/**
 * The owner application domain designates an application key
 * as one of Test, Dev or Prod.
 */
typedef enum owner_app_domain {
  /** Test domain: `test` */
  kOwnerAppDomainTest = 0x74736574,
  /** Dev domain: `dev_` */
  kOwnerAppDomainDev = 0x5f766564,
  /** Prod domain: `prod` */
  kOwnerAppDomainProd = 0x646f7270,
} owner_app_domain_t;
/**
 * The owner application key encodes keys for verifying the owner's application
 * firmware.
 */
typedef struct owner_application_key {
  /**
   * Header identifying this struct.
   * tag: `APPK`.
   * length: 48 + sizeof(key).
   */
  tlv_header_t header;
  /** Key algorithm.  One of ECDSA, SPX+ or SPXq20. */
  uint32_t key_alg;
  union {
    struct {
      /** Key domain.  Recognized values: PROD, DEV, TEST */
      uint32_t key_domain;
      /** Key diversifier.
       *
       * This value is concatenated to key_domain to create an 8 word
       * diversification constant to be programmed into the keymgr.
       */
      uint32_t key_diversifier[7];
    };
    uint32_t raw_diversifier[8];
  };
  /** Usage constraint must match manifest header's constraint */
  uint32_t usage_constraint;
  /** Key material.  Varies by algorithm type. */
  union {
    uint32_t id;
    sigverify_rsa_key_t rsa;
    sigverify_spx_key_t spx;
    ecdsa_p256_public_key_t ecdsa;
    hybrid_key_t hybrid;
  } data;
} owner_application_key_t;

OT_ASSERT_MEMBER_OFFSET(owner_application_key_t, header, 0);
OT_ASSERT_MEMBER_OFFSET(owner_application_key_t, key_alg, 8);
OT_ASSERT_MEMBER_OFFSET(owner_application_key_t, key_domain, 12);
OT_ASSERT_MEMBER_OFFSET(owner_application_key_t, key_diversifier, 16);
OT_ASSERT_MEMBER_OFFSET(owner_application_key_t, usage_constraint, 44);
OT_ASSERT_MEMBER_OFFSET(owner_application_key_t, data, 48);
OT_ASSERT_SIZE(owner_application_key_t, 464);

enum {
  kTlvLenApplicationKeyRsa =
      offsetof(owner_application_key_t, data) + sizeof(sigverify_rsa_key_t),
  kTlvLenApplicationKeySpx =
      offsetof(owner_application_key_t, data) + sizeof(sigverify_spx_key_t),
  kTlvLenApplicationKeyEcdsa =
      offsetof(owner_application_key_t, data) + sizeof(ecdsa_p256_public_key_t),
  kTlvLenApplicationKeyHybrid =
      offsetof(owner_application_key_t, data) + sizeof(hybrid_key_t),
};

// clang-format off
/**
 * Bitfields for the `access` word of flash region configs.
 */
#define FLASH_CONFIG_READ                 ((bitfield_field32_t) { .mask = 0xF, .index = 0 })
#define FLASH_CONFIG_PROGRAM              ((bitfield_field32_t) { .mask = 0xF, .index = 4 })
#define FLASH_CONFIG_ERASE                ((bitfield_field32_t) { .mask = 0xF, .index = 8 })
#define FLASH_CONFIG_PROTECT_WHEN_PRIMARY ((bitfield_field32_t) { .mask = 0xF, .index = 24 })
#define FLASH_CONFIG_LOCK                 ((bitfield_field32_t) { .mask = 0xF, .index = 28 })

/**
 * Bitfields for the `properties` word of flash region configs.
 */
#define FLASH_CONFIG_SCRAMBLE             ((bitfield_field32_t) { .mask = 0xF, .index = 0 })
#define FLASH_CONFIG_ECC                  ((bitfield_field32_t) { .mask = 0xF, .index = 4 })
#define FLASH_CONFIG_HIGH_ENDURANCE       ((bitfield_field32_t) { .mask = 0xF, .index = 8 })
// clang-format on

/**
 * The owner flash region describes a region of flash and its configuration
 * properties (ie: ECC, Scrambling, High Endurance, etc).
 */
typedef struct owner_flash_region {
  /** The start of the region, in flash pages. */
  uint16_t start;
  /** The size of the region, in flash pages. */
  uint16_t size;
  /** The access properties of the flash region. */
  uint32_t access;
  /** The flash properties of the flash region. */
  uint32_t properties;
} owner_flash_region_t;
OT_ASSERT_SIZE(owner_flash_region_t, 12);

/**
 * The owner flash config is a collection of owner region configuration items.
 */
typedef struct owner_flash_config {
  /**
   * Header identifiying this struct.
   * tag: `FLSH`.
   * length: 8 + 12 * length(config).
   */
  tlv_header_t header;
  /**
   * A list of flash region configurations.
   * In each `config` item, the `access` and `properties` fields are xor-ed
   * with the region index in each nibble (ie: index 1 == 0x11111111).
   */
  owner_flash_region_t config[];
} owner_flash_config_t;
OT_ASSERT_MEMBER_OFFSET(owner_flash_config_t, header, 0);
OT_ASSERT_MEMBER_OFFSET(owner_flash_config_t, config, 8);
OT_ASSERT_SIZE(owner_flash_config_t, 8);

/**
 * The owner info page describes an INFO page in flash and its configuration
 * properties (ie: ECC, Scrambling, High Endurance, etc).
 */
typedef struct owner_info_page {
  /** The bank where the info page is located. */
  uint8_t bank;
  /** The info page number. */
  uint8_t page;
  uint16_t _pad;
  /** The access properties of the flash region. */
  uint32_t access;
  /** The flash properties of the flash region. */
  uint32_t properties;
} owner_info_page_t;
OT_ASSERT_SIZE(owner_info_page_t, 12);

typedef struct owner_flash_info_config {
  /**
   * Header identifiying this struct.
   * tag: `INFO`.
   * length: 8 + 12 * length(config).
   */
  tlv_header_t header;
  /**
   * A list of flash info page configurations.
   * In each `config` item, the `access` and `properties` fields are xor-ed
   * with the region index in each nibble (ie: index 1 == 0x11111111).
   */
  owner_info_page_t config[];
} owner_flash_info_config_t;
OT_ASSERT_MEMBER_OFFSET(owner_flash_info_config_t, header, 0);
OT_ASSERT_MEMBER_OFFSET(owner_flash_info_config_t, config, 8);
OT_ASSERT_SIZE(owner_flash_info_config_t, 8);

/**
 * The owner rescue configuration describes how the rescue protocol should
 * behave when invoked in the ROM_EXT.
 */
typedef struct owner_rescue_config {
  /**
   * Header identifiying this struct.
   * tag: `RESQ`.
   * length: 16 + sizeof(command_allow).
   */
  tlv_header_t header;
  /** The rescue type.  Currently, only `XMDM` is supported. */
  uint32_t rescue_type;
  /** The start offset of the rescue region in flash (in pages). */
  uint16_t start;
  /** The size of the rescue region in flash (in pages). */
  uint16_t size;
  /** An allowlist of rescue and boot_svc commands that may be invoked by the
   * rescue protocol.  The commands are identified by their 4-byte tags (tag
   * identifiers between rescue commands and boot_svc commands are unique).
   */
  uint32_t command_allow[];
} owner_rescue_config_t;
OT_ASSERT_MEMBER_OFFSET(owner_rescue_config_t, header, 0);
OT_ASSERT_MEMBER_OFFSET(owner_rescue_config_t, rescue_type, 8);
OT_ASSERT_MEMBER_OFFSET(owner_rescue_config_t, start, 12);
OT_ASSERT_MEMBER_OFFSET(owner_rescue_config_t, size, 14);
OT_ASSERT_MEMBER_OFFSET(owner_rescue_config_t, command_allow, 16);
OT_ASSERT_SIZE(owner_rescue_config_t, 16);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_OWNERSHIP_DATATYPES_H_
