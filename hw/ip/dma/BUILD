# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "rtl_files",
    srcs = glob(
        ["**"],
        exclude = [
            "dv/**",
            "doc/**",
            "README.md",
        ],
    ) + [
        "//hw/ip/dma/data:all_files",
    ],
)

filegroup(
    name = "cores",
    srcs = glob(["**/*.core"]),
)

filegroup(
    name = "doc_files",
    srcs = glob(["**/*.md"]) + ["//hw/ip/dma/data:dma_testplan.hjson"],
)
