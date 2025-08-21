# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@ot_python_deps//:requirements.bzl", "requirement")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "fi_ibex_test_script",
    srcs = ["test_scripts/fi_ibex_test.py"],
)

filegroup(
    name = "fi_crypto_test_script",
    srcs = ["test_scripts/fi_crypto_test.py"],
)

filegroup(
    name = "fi_otbn_test_script",
    srcs = ["test_scripts/fi_otbn_test.py"],
)

filegroup(
    name = "fi_otp_test_script",
    srcs = ["test_scripts/fi_otp_test.py"],
)

filegroup(
    name = "fi_rom_test_script",
    srcs = ["test_scripts/fi_rom_test.py"],
)

filegroup(
    name = "fi_alert_test_script",
    srcs = ["test_scripts/fi_alert_test.py"],
)

filegroup(
    name = "fi_rng_test_script",
    srcs = ["test_scripts/fi_rng_test.py"],
)

py_library(
    name = "fi_ibex_functions",
    srcs = ["host_scripts/fi_ibex_functions.py"],
    deps = [
        ":fi_ibex_commands",
        "//sw/host/penetrationtests/python/util:common_library",
        "//sw/host/penetrationtests/python/util:targets",
    ],
)

py_library(
    name = "fi_crypto_functions",
    srcs = ["host_scripts/fi_crypto_functions.py"],
    deps = [
        ":fi_crypto_commands",
        "//sw/host/penetrationtests/python/util:common_library",
        "//sw/host/penetrationtests/python/util:targets",
    ],
)

py_library(
    name = "fi_otbn_functions",
    srcs = ["host_scripts/fi_otbn_functions.py"],
    deps = [
        ":fi_otbn_commands",
        "//sw/host/penetrationtests/python/util:common_library",
        "//sw/host/penetrationtests/python/util:targets",
    ],
)

py_library(
    name = "fi_otp_functions",
    srcs = ["host_scripts/fi_otp_functions.py"],
    deps = [
        ":fi_otp_commands",
        "//sw/host/penetrationtests/python/util:common_library",
        "//sw/host/penetrationtests/python/util:targets",
    ],
)

py_library(
    name = "fi_rom_functions",
    srcs = ["host_scripts/fi_rom_functions.py"],
    deps = [
        ":fi_rom_commands",
        "//sw/host/penetrationtests/python/util:common_library",
        "//sw/host/penetrationtests/python/util:targets",
    ],
)

py_library(
    name = "fi_alert_functions",
    srcs = ["host_scripts/fi_alert_functions.py"],
    deps = [
        ":fi_alert_commands",
        "//sw/host/penetrationtests/python/util:common_library",
        "//sw/host/penetrationtests/python/util:targets",
    ],
)

py_library(
    name = "fi_rng_functions",
    srcs = ["host_scripts/fi_rng_functions.py"],
    deps = [
        ":fi_rng_commands",
        "//sw/host/penetrationtests/python/util:common_library",
        "//sw/host/penetrationtests/python/util:targets",
    ],
)

py_library(
    name = "fi_ibex_commands",
    srcs = ["communication/fi_ibex_commands.py"],
    deps = ["//sw/host/penetrationtests/python/util:common_library"],
)

py_library(
    name = "sca_ibex_commands",
    srcs = ["communication/sca_ibex_commands.py"],
    deps = ["//sw/host/penetrationtests/python/util:common_library"],
)

py_library(
    name = "fi_crypto_commands",
    srcs = ["communication/fi_crypto_commands.py"],
    deps = ["//sw/host/penetrationtests/python/util:common_library"],
)

py_library(
    name = "fi_otbn_commands",
    srcs = ["communication/fi_otbn_commands.py"],
    deps = ["//sw/host/penetrationtests/python/util:common_library"],
)

py_library(
    name = "fi_otp_commands",
    srcs = ["communication/fi_otp_commands.py"],
    deps = ["//sw/host/penetrationtests/python/util:common_library"],
)

py_library(
    name = "fi_rng_commands",
    srcs = ["communication/fi_rng_commands.py"],
    deps = ["//sw/host/penetrationtests/python/util:common_library"],
)

py_library(
    name = "fi_rom_commands",
    srcs = ["communication/fi_rom_commands.py"],
    deps = ["//sw/host/penetrationtests/python/util:common_library"],
)

py_library(
    name = "fi_alert_commands",
    srcs = ["communication/fi_alert_commands.py"],
    deps = ["//sw/host/penetrationtests/python/util:common_library"],
)
