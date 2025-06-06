// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// This has some assertions that check that the output clock enables correspond
// to the control CSR when transitioning into or out of the active state. In
// addition, the usb clock can change anytime when in the active state.
interface pwrmgr_clock_enables_sva_if (
  input logic                        clk_i,
  input logic                        rst_ni,
  input pwrmgr_pkg::fast_pwr_state_e fast_state,
  input pwrmgr_pkg::slow_pwr_state_e slow_state,
  // The synchronized control CSR bits.
  input logic                        main_pd_ni,
% for clk in src_clks:
  % if clk == 'usb':
  input logic                        usb_clk_en_lp_i,
  input logic                        usb_clk_en_active_i,
  input logic                        usb_ip_clk_status_i,
  % else:
  input logic                        ${clk}_clk_en_i,
  % endif
% endfor
  // The output enables.
  input logic                        main_pd_n,
% for clk in src_clks:
  input logic                        ${clk}_clk_en${'' if loop.last else ','}
% endfor
);

  bit disable_sva;
  bit reset_or_disable;

  always_comb reset_or_disable = !rst_ni || disable_sva;

  sequence transitionUp_S; slow_state == pwrmgr_pkg::SlowPwrStateReqPwrUp; endsequence

  sequence transitionDown_S; slow_state == pwrmgr_pkg::SlowPwrStatePwrClampOn; endsequence

  bit fast_is_active;
  always_comb fast_is_active = fast_state == pwrmgr_pkg::FastPwrStateActive;

% for clk in src_clks:
  % if clk == 'usb':
  `ASSERT(UsbClkPwrUp_A, transitionUp_S |=> usb_clk_en == usb_clk_en_active_i, clk_i,
          reset_or_disable)
  % else:
  `ASSERT(${clk.capitalize()}ClkPwrUp_A, transitionUp_S |=> ${clk}_clk_en == 1'b1, clk_i, reset_or_disable)
  % endif
% endfor

% if 'usb' in src_clks:
  // This deals with transitions while the fast fsm is active.
  // Allow the usb enable to be slower since it also depends on usb clk_status.
  sequence usbActiveTransition_S;
    ${"##"}[0:7] !fast_is_active || usb_clk_en == (usb_clk_en_active_i | usb_ip_clk_status_i);
  endsequence
  `ASSERT(UsbClkActive_A, fast_is_active && $changed(usb_clk_en_active_i) |=> usbActiveTransition_S,
          clk_i, reset_or_disable)

% endif
% for clk in src_clks:
  % if clk == 'usb':
  `ASSERT(${clk.capitalize()}ClkPwrDown_A, transitionDown_S |=> ${clk}_clk_en == (usb_clk_en_lp_i && main_pd_ni),
          clk_i, reset_or_disable)
  % else:
  `ASSERT(${clk.capitalize()}ClkPwrDown_A, transitionDown_S |=> ${clk}_clk_en == (${clk}_clk_en_i && main_pd_ni),
          clk_i, reset_or_disable)
  % endif
% endfor
endinterface
