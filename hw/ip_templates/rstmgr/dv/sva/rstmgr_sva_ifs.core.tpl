CAPI=2:
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
name: ${instance_vlnv("lowrisc:dv:rstmgr_sva_ifs:0.1")}
description: "RSTMGR cascading resets assertion interface."
filesets:
  files_dv:
    depend:
      - lowrisc:ip:lc_ctrl_pkg
      - ${instance_vlnv("lowrisc:ip:pwrmgr_pkg")}
      - lowrisc:dv:pwrmgr_rstmgr_sva_if
      - ${instance_vlnv("lowrisc:ip:rstmgr")}

    files:
      - rstmgr_attrs_sva_if.sv
      - rstmgr_cascading_sva_if.sv
      - rstmgr_rst_en_track_sva_if.sv
      - rstmgr_sw_rst_sva_if.sv
    file_type: systemVerilogSource

targets:
  default:
    filesets:
      - files_dv
