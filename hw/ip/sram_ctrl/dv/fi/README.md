# Synopsys VC Z01X SRAM_CTRL Fault Injection Simulation

This setup analyzes the fault resilience of the SRAM controller (`sram_ctrl`) and its sub-word
Read-Modify-Write adapter (`tlul_sram_byte`) using Synopsys VC Z01X.

## Usage

Prepare the OpenTitan checkout with the Z01X overlay:
```bash
$ export Z01X_DIR=<path to opentitan_fi_z01x>
$ export OT_DIR=<path to opentitan>
$ cd $OT_DIR
$ ./util/prepare_dvsim_z01x.sh
```

Run the partial-access fault injection campaign (`sram_ctrl_partial_access`), which exercises
sub-word Read-Modify-Write transactions through `tlul_sram_byte`:
```bash
$ dvsim hw/ip/sram_ctrl/dv/sram_ctrl_main_fi_sim_cfg.hjson \
    -i sram_ctrl_partial_access -t z01x --max-parallel 1 --fixed-seed 1
```
The results are written to `fsim_result.rpt` in the run directory.
