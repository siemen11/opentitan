# Penetrationtests

## Overview
This directory contains Python scripts to work with the testOS from //sw/device/tests/penetrationtests which contains the chip/fpga interface for performing side-channel and fault injection tests. These scripts are reflected in the ot-sca repo (https://github.com/lowRISC/ot-sca).

### target
Contains the basic scripts to interact with the chip or fpga such as reading or sending data or resetting/reflashing the device.

### fi/sca
The directory for fault injection or side-channel analysis related tests.

#### communication
Contains the scipts for the UART output to the chip/fpga to execute tests.

#### host_scripts
Combines functions from the communication directory to perform simple tests.

#### test_scripts
Tests the host scripts to keep communication and host_scripts up-to-date.
