CAPI=2:
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
name: ${instance_vlnv("lowrisc:dv:otp_ctrl_sva:0.1")}
description: "OTP_CTRL assertion modules and bind file."

filesets:
  files_dv:
    depend:
      - lowrisc:tlul:headers
      - lowrisc:fpv:csr_assert_gen
    files:
      - otp_ctrl_bind.sv
    file_type: systemVerilogSource

  files_formal:
    depend:
      - ${instance_vlnv("lowrisc:ip:otp_ctrl")}

generate:
  csr_assert_gen:
    generator: csr_assert_gen
    parameters:
      spec: ../../data/otp_ctrl.hjson

targets:
  default: &default_target
    filesets:
      - files_dv
    generate:
      - csr_assert_gen

  formal:
    <<: *default_target
    filesets:
      - files_formal
      - files_dv
    toplevel: otp_ctrl
