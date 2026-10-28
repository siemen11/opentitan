// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

module strobe;

  // Enable TL-UL integrity checker strobing points.
  `define FI_SIM_Z01X

  initial begin
    @(posedge tb.dut.rst_ni)
    // Start FI injection job. For permanent faults, faults are injected
    // at this point. For transient faults, the cycle counter starts from
    // here.
    $fs_inject;
  end

  integer cmp;
  string status;

  always @(negedge tb.dut.clk_i) begin
    // Compare downstream SRAM outputs of the golden and faulty machine.
    cmp = $fs_compare(tb.dut.sram_req, tb.dut.sram_we, tb.dut.sram_addr, tb.dut.sram_wdata,
                      tb.dut.sram_rdata, tb.dut.sram_rvalid);
    if (1 == cmp) begin
      // Mismatch between the golden and faulty machine.
      $fs_set_status("ON", tb.dut.sram_req, tb.dut.sram_we, tb.dut.sram_addr, tb.dut.sram_wdata,
                     tb.dut.sram_rdata, tb.dut.sram_rvalid);
    end else if (2 == cmp) begin
      // Faulty machine has an X/Z at the output.
      $fs_set_status("PN", tb.dut.sram_req, tb.dut.sram_we, tb.dut.sram_addr, tb.dut.sram_wdata,
                     tb.dut.sram_rdata, tb.dut.sram_rvalid);
    end

    // Check if one of the countermeasures has detected the fault.
    status = $fs_get_status();
    cmp = $fs_compare(tb.dut.readback_error, tb.dut.bus_integ_error,
                      tb.dut.sram_rerror_o, tb.dut.ram_tl_intg_err, tb.dut.regs_tl_intg_err);
    if (1 == cmp) begin
      if (status == "ON") begin
        $fs_drop_status("OD", tb.dut.readback_error, tb.dut.bus_integ_error,
                        tb.dut.sram_rerror_o, tb.dut.ram_tl_intg_err, tb.dut.regs_tl_intg_err);
      end else if (status == "PN") begin
        $fs_drop_status("PD", tb.dut.readback_error, tb.dut.bus_integ_error,
                        tb.dut.sram_rerror_o, tb.dut.ram_tl_intg_err, tb.dut.regs_tl_intg_err);
      end else if (status == "NN") begin
        $fs_drop_status("ND", tb.dut.readback_error, tb.dut.bus_integ_error,
                        tb.dut.sram_rerror_o, tb.dut.ram_tl_intg_err, tb.dut.regs_tl_intg_err);
      end
    end else if (2 == cmp) begin
      if (status == "ON") begin
        $fs_set_status("OP", tb.dut.readback_error, tb.dut.bus_integ_error,
                       tb.dut.sram_rerror_o, tb.dut.ram_tl_intg_err, tb.dut.regs_tl_intg_err);
      end else if (status == "PN") begin
        $fs_set_status("PP", tb.dut.readback_error, tb.dut.bus_integ_error,
                       tb.dut.sram_rerror_o, tb.dut.ram_tl_intg_err, tb.dut.regs_tl_intg_err);
      end else if (status == "NN") begin
        $fs_set_status("NP", tb.dut.readback_error, tb.dut.bus_integ_error,
                       tb.dut.sram_rerror_o, tb.dut.ram_tl_intg_err, tb.dut.regs_tl_intg_err);
      end
    end
  end

endmodule
