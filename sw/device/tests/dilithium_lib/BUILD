# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "poly",
    srcs = ["poly.c"],
    hdrs = [
        "poly.h",
        "config.h",
        "params.h",
    ],
    deps = [
        "//sw/device/tests/dilithium_lib:ntt",
        "//sw/device/tests/dilithium_lib:rounding",
        "//sw/device/tests/dilithium_lib:symmetric",
    ],
)

cc_library(
    name = "polyvec",
    srcs = ["polyvec.c"],
    hdrs = [
        "polyvec.h",
        "config.h",
        "params.h",
    ],
    deps = [
        "//sw/device/tests/dilithium_lib:poly",
    ],
)

cc_library(
    name = "ntt",
    srcs = ["ntt.c"],
    hdrs = [
        "ntt.h",
        "config.h",
        "params.h",
    ],
    deps = [
        "//sw/device/tests/dilithium_lib:reduce"
    ],
)

cc_library(
    name = "reduce",
    srcs = ["reduce.c"],
    hdrs = [
        "reduce.h",
        "config.h",
        "params.h",
    ],
)

cc_library(
    name = "rounding",
    srcs = ["rounding.c"],
    hdrs = [
        "rounding.h",
        "config.h",
        "params.h",
    ],
)

cc_library(
    name = "fips202",
    srcs = ["fips202.c"],
    hdrs = ["fips202.h"],
)

cc_library(
    name = "symmetric",
    srcs = ["symmetric-shake.c"],
    hdrs = [
        "symmetric.h",
        "config.h",
        "params.h",
    ],
    deps = [
        "//sw/device/tests/dilithium_lib:fips202"
    ],
)

cc_library(
    name = "packing",
    srcs = ["packing.c"],
    hdrs = [
        "packing.h",
        "config.h",
        "params.h",
    ],
    deps = [
        "//sw/device/tests/dilithium_lib:polyvec",
    ],
)
