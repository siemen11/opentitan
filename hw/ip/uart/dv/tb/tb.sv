// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
module tb;
  // dep packages
  import uvm_pkg::*;
  import dv_utils_pkg::*;
  import tl_agent_pkg::*;
  import uart_env_pkg::*;
  import uart_test_pkg::*;

  // macro includes
  `include "uvm_macros.svh"
  `include "dv_macros.svh"

  wire clk, rst_n;
  wire intr_tx_watermark;
  wire intr_tx_empty;
  wire intr_rx_watermark;
  wire intr_tx_done;
  wire intr_rx_overflow;
  wire intr_rx_frame_err;
  wire intr_rx_break_err;
  wire intr_rx_timeout;
  wire intr_rx_parity_err;
  wire uart_rx, uart_tx, uart_tx_en;
  wire [NUM_MAX_INTERRUPTS-1:0] interrupts;

  // interfaces
  clk_rst_if clk_rst_if(.clk, .rst_n);
  pins_if #(NUM_MAX_INTERRUPTS) intr_if(interrupts);
  tl_if tl_if(.clk, .rst_n);
  uart_if uart_if();
  uart_nf_if uart_nf_if(.clk_i(clk), .rst_ni(rst_n));

 `DV_ALERT_IF_CONNECT()

  // dut
  uart dut (
    .clk_i                (clk        ),
    .rst_ni               (rst_n      ),

    .tl_i                 (tl_if.h2d  ),
    .tl_o                 (tl_if.d2h  ),

    .alert_rx_i           (alert_rx   ),
    .alert_tx_o           (alert_tx   ),

    // RACL interface
    .racl_policies_i      ('0         ),
    .racl_error_o         (           ),

    .lsio_trigger_o       (           ),

    .cio_rx_i             (uart_rx    ),
    .cio_tx_o             (uart_tx    ),
    .cio_tx_en_o          (uart_tx_en ),

    .intr_tx_watermark_o  (intr_tx_watermark ),
    .intr_tx_empty_o      (intr_tx_empty     ),
    .intr_rx_watermark_o  (intr_rx_watermark ),
    .intr_tx_done_o       (intr_tx_done      ),
    .intr_rx_overflow_o   (intr_rx_overflow  ),
    .intr_rx_frame_err_o  (intr_rx_frame_err ),
    .intr_rx_break_err_o  (intr_rx_break_err ),
    .intr_rx_timeout_o    (intr_rx_timeout   ),
    .intr_rx_parity_err_o (intr_rx_parity_err)
  );

  assign interrupts[TxWatermark] = intr_tx_watermark;
  assign interrupts[TxEmpty]     = intr_tx_empty;
  assign interrupts[RxWatermark] = intr_rx_watermark;
  assign interrupts[TxDone]      = intr_tx_done;
  assign interrupts[RxOverflow]  = intr_rx_overflow;
  assign interrupts[RxFrameErr]  = intr_rx_frame_err;
  assign interrupts[RxBreakErr]  = intr_rx_break_err;
  assign interrupts[RxTimeout]   = intr_rx_timeout;
  assign interrupts[RxParityErr] = intr_rx_parity_err;

  assign uart_rx = uart_if.uart_rx;
  assign uart_if.uart_tx = uart_tx;

  assign uart_nf_if.rx_sync    = dut.uart_core.rx_sync;
  assign uart_nf_if.rx_sync_q1 = dut.uart_core.rx_sync_q1;
  assign uart_nf_if.rx_sync_q2 = dut.uart_core.rx_sync_q2;
  assign uart_nf_if.rx_enable  = dut.uart_core.rx_enable;

  initial begin
    // drive clk and rst_n from clk_if
    clk_rst_if.set_active();
    uvm_config_db#(virtual clk_rst_if)::set(null, "*.env", "clk_rst_vif", clk_rst_if);
    uvm_config_db#(intr_vif)::set(null, "*.env", "intr_vif", intr_if);
    uvm_config_db#(virtual tl_if)::set(null, "*.env.m_tl_agent*", "vif", tl_if);
    uvm_config_db#(virtual uart_if)::set(null, "*.env.m_uart_agent*", "vif", uart_if);
    uvm_config_db#(virtual uart_nf_if)::set(null, "*.scoreboard", "uart_nf_vif", uart_nf_if);
    $timeformat(-12, 0, " ps", 12);
    run_test();
  end

  // we expect the output enable to be always 1
  `ASSERT(UartTxEnTiedTo1_A, uart_tx_en, clk, !rst_n)

endmodule
