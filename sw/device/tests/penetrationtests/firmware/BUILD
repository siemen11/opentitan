# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load(
    "@bazel_skylib//lib:dicts.bzl",
    "dicts",
)
load(
    "//rules/opentitan:defs.bzl",
    "EARLGREY_SILICON_OWNER_ROM_EXT_ENVS",
    "EARLGREY_TEST_ENVS",
    "fpga_params",
    "opentitan_binary",
    "opentitan_test",
    "silicon_params",
)
load("//rules:const.bzl", "CONST", "hex")
load("//rules:signing.bzl", "offline_presigning_artifacts", "offline_signature_attach")
load("//rules:manifest.bzl", "manifest")
load(
    "//sw/device/silicon_creator/rom_ext:defs.bzl",
    "ROM_EXT_VARIATIONS",
    "ROM_EXT_VERSION",
    "SLOTS",
)
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

package(default_visibility = ["//visibility:public"])

PENTEST_EXEC_ENVS = dicts.add(
    EARLGREY_TEST_ENVS,
    EARLGREY_SILICON_OWNER_ROM_EXT_ENVS,
)

FIRMWARE_DEPS_FI = [
    "//sw/device/tests/penetrationtests/firmware/fi:crypto_fi",
    "//sw/device/tests/penetrationtests/firmware/fi:lc_ctrl_fi",
    "//sw/device/tests/penetrationtests/firmware/fi:otp_fi",
    "//sw/device/tests/penetrationtests/firmware/fi:rng_fi",
    "//sw/device/tests/penetrationtests/firmware/fi:rom_fi",
    "//sw/device/tests/penetrationtests/firmware/lib:extclk_sca_fi",
    "//sw/device/tests/penetrationtests/firmware/lib:pentest_lib",
    "//sw/device/lib/base:csr",
    "//sw/device/lib/base:status",
    "//sw/device/lib/crypto/drivers:entropy",
    "//sw/device/lib/testing/test_framework:check",
    "//sw/device/lib/testing/test_framework:ottf_main",
    "//sw/device/lib/testing/test_framework:ujson_ottf",
    "//sw/device/lib/ujson",

    # Include all JSON commands.
    "//sw/device/tests/penetrationtests/json:commands",
]

FIRMWARE_DEPS_FI_IBEX = [
    "//sw/device/tests/penetrationtests/firmware/fi:ibex_fi",
    "//sw/device/tests/penetrationtests/firmware/lib:pentest_lib",
    "//sw/device/lib/base:csr",
    "//sw/device/lib/base:status",
    "//sw/device/lib/crypto/drivers:entropy",
    "//sw/device/lib/testing/test_framework:check",
    "//sw/device/lib/testing/test_framework:ottf_main",
    "//sw/device/lib/testing/test_framework:ujson_ottf",
    "//sw/device/lib/ujson",

    # Include all JSON commands.
    "//sw/device/tests/penetrationtests/json:commands",
]

FIRMWARE_DEPS_FI_OTBN = [
    "//sw/device/tests/penetrationtests/firmware/fi:otbn_fi",
    "//sw/device/tests/penetrationtests/firmware/lib:pentest_lib",
    "//sw/device/lib/base:csr",
    "//sw/device/lib/base:status",
    "//sw/device/lib/crypto/drivers:entropy",
    "//sw/device/lib/testing/test_framework:check",
    "//sw/device/lib/testing/test_framework:ottf_main",
    "//sw/device/lib/testing/test_framework:ujson_ottf",
    "//sw/device/lib/ujson",

    # Include all JSON commands.
    "//sw/device/tests/penetrationtests/json:commands",
]

FIRMWARE_DEPS_SCA = [
    "//sw/device/tests/penetrationtests/firmware/sca:aes_sca",
    "//sw/device/tests/penetrationtests/firmware/sca:edn_sca",
    "//sw/device/tests/penetrationtests/firmware/sca:hmac_sca",
    "//sw/device/tests/penetrationtests/firmware/sca:ibex_sca",
    "//sw/device/tests/penetrationtests/firmware/sca:kmac_sca",
    "//sw/device/tests/penetrationtests/firmware/sca:otbn_sca",
    "//sw/device/tests/penetrationtests/firmware/sca:prng_sca",
    "//sw/device/tests/penetrationtests/firmware/sca:sha3_sca",
    "//sw/device/tests/penetrationtests/firmware/sca:trigger_sca",
    "//sw/device/tests/penetrationtests/firmware/lib:extclk_sca_fi",
    "//sw/device/tests/penetrationtests/firmware/lib:pentest_lib",
    "//sw/device/lib/base:csr",
    "//sw/device/lib/base:status",
    "//sw/device/lib/crypto/drivers:entropy",
    "//sw/device/lib/testing/test_framework:check",
    "//sw/device/lib/testing/test_framework:ottf_main",
    "//sw/device/lib/testing/test_framework:ujson_ottf",
    "//sw/device/lib/ujson",

    # Include all JSON commands.
    "//sw/device/tests/penetrationtests/json:commands",
]

opentitan_binary(
    name = "firmware_fi",
    testonly = True,
    srcs = [":firmware_fi.c"],
    exec_env = [
        "//hw/top_earlgrey:fpga_cw310",
        "//hw/top_earlgrey:fpga_cw340",
        "//hw/top_earlgrey:silicon_owner_sival_rom_ext",
    ],
    deps = FIRMWARE_DEPS_FI,
)

opentitan_binary(
    name = "firmware_fi_ibex",
    testonly = True,
    srcs = [":firmware_fi_ibex.c"],
    exec_env = [
        "//hw/top_earlgrey:fpga_cw310",
        "//hw/top_earlgrey:fpga_cw340",
        "//hw/top_earlgrey:silicon_owner_sival_rom_ext",
    ],
    deps = FIRMWARE_DEPS_FI_IBEX,
)

opentitan_binary(
    name = "firmware_fi_otbn",
    testonly = True,
    srcs = [":firmware_fi_otbn.c"],
    exec_env = [
        "//hw/top_earlgrey:fpga_cw310",
        "//hw/top_earlgrey:fpga_cw340",
        "//hw/top_earlgrey:silicon_owner_sival_rom_ext",
    ],
    deps = FIRMWARE_DEPS_FI_OTBN,
)

opentitan_binary(
    name = "firmware_sca",
    testonly = True,
    srcs = [":firmware_sca.c"],
    exec_env = [
        "//hw/top_earlgrey:fpga_cw310",
        "//hw/top_earlgrey:fpga_cw340",
        "//hw/top_earlgrey:silicon_owner_sival_rom_ext",
        "//hw/top_earlgrey:silicon_owner_pixel_rom_ext",
    ],
    deps = FIRMWARE_DEPS_SCA,
)

opentitan_test(
    name = "chip_pen_test_fi",
    srcs = [":firmware_fi.c"],
    exec_env = PENTEST_EXEC_ENVS,
    fpga = fpga_params(tags = ["skip_in_ci"]),
    silicon = silicon_params(
        tags = [
            "manual",
            "skip_in_ci",
        ],
    ),
    deps = FIRMWARE_DEPS_FI,
)

opentitan_test(
    name = "chip_pen_test_fi_ibex",
    srcs = [":firmware_fi_ibex.c"],
    exec_env = PENTEST_EXEC_ENVS,
    fpga = fpga_params(tags = ["skip_in_ci"]),
    silicon = silicon_params(
        tags = [
            "manual",
            "skip_in_ci",
        ],
    ),
    deps = FIRMWARE_DEPS_FI_IBEX,
)

opentitan_test(
    name = "chip_pen_test_fi_otbn",
    srcs = [":firmware_fi_otbn.c"],
    exec_env = PENTEST_EXEC_ENVS,
    fpga = fpga_params(tags = ["skip_in_ci"]),
    silicon = silicon_params(
        tags = [
            "manual",
            "skip_in_ci",
        ],
    ),
    deps = FIRMWARE_DEPS_FI_OTBN,
)

opentitan_test(
    name = "chip_pen_test_sca",
    srcs = [":firmware_sca.c"],
    exec_env = PENTEST_EXEC_ENVS,
    fpga = fpga_params(tags = ["skip_in_ci"]),
    silicon = silicon_params(
        tags = [
            "manual",
            "skip_in_ci",
        ],
    ),
    deps = FIRMWARE_DEPS_SCA,
)

manifest(d = {
    "name": "manifest",
    "identifier": hex(CONST.ROM_EXT),
    "version_major": ROM_EXT_VERSION.MAJOR,
    "version_minor": ROM_EXT_VERSION.MINOR,
    "security_version": ROM_EXT_VERSION.SECURITY,
    "visibility": ["//visibility:public"],
})

offline_presigning_artifacts(
    name = "chip_pen_test_sca_presigning",
    testonly = True,
    srcs = [
        ":chip_pen_test_sca_silicon_owner_a2_rom_ext",
    ],
    # TODO: change to real keys
    ecdsa_key = {
        "//sw/device/silicon_creator/rom/keys/fake/ecdsa:test_key_0_ecdsa_p256": "fake_test_key_0",
    },
    spx_key = {
        "//sw/device/silicon_creator/rom/keys/fake/spx:test_key_0_spx": "test_key_0_spx_key",
    },
    manifest = ":manifest",
    tags = ["manual"],
)

pkg_tar(
    name = "sca_digest",
    testonly = True,
    srcs = [":chip_pen_test_sca_presigning"],
    mode = "0644",
    tags = ["manual"],
)