// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
{
  name: "${module_instance_name}"
  import_testplans: ["hw/dv/tools/dvsim/testplans/csr_testplan.hjson",
                     "hw/dv/tools/dvsim/testplans/alert_test_testplan.hjson",
                     "hw/dv/tools/dvsim/testplans/intr_test_testplan.hjson",
                     "hw/dv/tools/dvsim/testplans/stress_all_with_reset_testplan.hjson",
                     "hw/dv/tools/dvsim/testplans/tl_device_access_types_testplan.hjson",
                     "gpio_sec_cm_testplan.hjson"]
  testpoints: [
    {
      name: smoke
      desc: '''GPIO smoke test that exercises gpio pins as inputs or outputs, and performs
            data integrity checks by triggering scoreboard checks by reading data_in register.
            This test repeats following steps are random no. of times:
            - Configures all gpio pins as inputs, drives random value on cio_gpio_i signal and
              reads data_in register after random delay
            - Configures all gpio pins as outputs, programs direct_out and direct_oe registers to
              random values and reads data_in register after random delay
            The test is also run in a second build mode that enables the input synchronizers in
            order to cover the input paths through these primitives.
            '''
      stage: V1
      tests: ["gpio_smoke",
              "gpio_smoke_no_pullup_pulldown",
              "gpio_smoke_en_cdc_prim",
              "gpio_smoke_no_pullup_pulldown_en_cdc_prim"]
    }
    {
      name: direct_and_masked_out
      desc: '''GPIO test that programs `DIRECT_OUT`, `DIRECT_OE`, `MASKED_OUT_LOWER`,
            `MASKED_OE_LOWER`, `MASKED_OUT_UPPER` and `MASKED_OE_UPPER` registers and checks their
            effect on GPIO pins as well as DATA_IN register value.
            Every random iteration in this test would either:
            - Program one or more of `\*OUT\*` and `\*OE\*` registers, or
            - Drive new random value on GPIO pins'''
      stage: V2
      tests: ["gpio_random_dout_din",
              "gpio_random_dout_din_no_pullup_pulldown"]
    }
    {
      name: out_in_regs_read_write
      desc: '''GPIO test that exercises functionality of DATA_OUT and DATA_OE internal registers,
            and `DATA_IN` register by programming any of `\*OUT\` and `\*OE\*` registers,
            respectively.
            Every random iteration in this test would perform one out of following operations:
            - Drive new random value on GPIO pins
            - Write random value to any one of `\*OUT\*`, `\*OE\*` or `DATA_IN` registers
            - Read any one of `\*OUT\*`, `\*OE\*` or `DATA_IN` registers'''
      stage: V2
      tests: ["gpio_dout_din_regs_random_rw"]
    }
    {
      name: gpio_interrupt_programming
      desc: '''GPIO test which programs one or multiple interrupt registers to check GPIO interrupt
            functionality
            Every random iteration in this test would do either of following steps, and then read
            `INTR_STATE` register value:
            - Drive new random value on GPIO pins (and thereby generate random interrupt event)
            - Write random value to one or more interrupt registers that include `INTR_ENABLE`,
              `INTR_CTRL_EN_FALLING`, `INTR_CTRL_EN_LVL_LOW`, `INTR_CTRL_EN_LVL_HIGH` and
              `INTR_STATE`'''
      stage: V2
      tests: ["gpio_intr_rand_pgm"]
    }
    {
      name: random_interrupt_trigger
      desc: '''GPIO test that randomly generates and clears multiple GPIO interrupts for each
            random programming of interrupt registers, and performs checks by reading `DATA_IN`
            and `INTR_STATE` registers.
            Each random iteration of this test performs following operations:
            1. Programs one more interrupt registers to random values
            2. Following two operations are performed in parallel:
               - Drive random value on GPIO pins multiple times, every time at a random time
                 intervals (random number of clock cycles)
               - Randomize random time interval (random number of clock cycles) and read either
                 `DATA_IN` or `INTR_STATE` register value at randomized time interval
                 After every read, optionally perform random interrupt clearing operation by
                 writing to `INTR_STATE` register'''
      stage: V2
      tests: ["gpio_rand_intr_trigger"]
    }
    {
      name: interrupt_and_noise_filter
      desc: '''GPIO test that exercise GPIO noise filter functionaliy along with random interrupt
            programming and randomly toggling each GPIO pin value, independently of other GPIO pins.
            Each random iteration performs following operations:
            1. programs random values in one or more interrupt registers
            2. optionally, programs new random value in `CTRL_EN_INPUT_FILTER` register
            3. performs following operations in parallel:
               - drives each GPIO pin independently such that each pin has stable value for random
                 number of clock cycles within the range `[1:FILTER_CYCLES]`, and also predicts
                 updates in values of `DATA_IN` and `INTR_STATE` registers
               - multiple registers reads, each for either `DATA_IN` or `INTR_STATE`'''
      stage: V2
      tests: ["gpio_intr_with_filter_rand_intr_event"]
    }
    {
      name: noise_filter_stress
      desc: '''GPIO test that stresses noise filter functionality by driving each GPIO pin such
            independently of other pins, and driving could be either synchronous to clock or
            asynchronous.
            Each iteration in test does following:
            1. Programs one or more interrupt registers with random values
            2. Programs noise filter register with random value
            3. Drives each  GPIO pin with the mix of both synchronous and asynchronous driving,
               and each pin is driven independently of others'''
      stage: V2
      tests: ["gpio_filter_stress"]
    }
    {
      name: regs_long_reads_and_writes
      desc: '''GPIO test that performs back-to-back register writes and back-to-back register reads
            on randomly selected GPIO registers.
            Each iteration in this test performs one out of following operations:
            - Drive new random value on GPIO pins
            - Perform multiple random writes on randomly selected GPIO registers
            - Perform multiple random reads on randomly selected GPIO registers'''
      stage: V2
      tests: ["gpio_random_long_reg_writes_reg_reads"]
    }
    {
      name: full_random
      desc: '''GPIO full random test that performs any of following in each iteration:
            - Drive new random value on GPIO pins such that GPIO inputs and GPIO outputs shall not
              result in unknown value on any pin
            - Write to one or more of `DIRECT_OUT`, `DIRECT_OE`, `MASKED_OUT_UPPER`,
              `MASKED_OE_UPPER`, `MASKED_OE_LOWER` and `MASKED_OE_LOWER` registers such that GPIO
              inputs and GPIO outputs shall not result in unknown value on any pin
            - Write to one or more of GPIO interrupt registers that include `INTR_ENABLE`,
              `INTR_CTRL_EN_FALLING`, `INTR_CTRL_EN_RISING`, `INTR_CTRL_EN_LVL_HIGH`,
              `INTR_CTRL_EN_LVL_LOW` and `INTR_STATE`
            - Write to other GPIO registers `DATA_IN`, `INTR_TEST`, `CTRL_EN_INPUT_FILTER`
            - Read any one of the GPIO registers
            - Apply hard reset'''
      stage: V2
      tests: ["gpio_full_random"]
    }
    {
      name: stress_all
      desc: '''Stress_all test is a random mix of all the test above except csr tests, gpio full
            random, intr_test and other gpio test that disabled scoreboard'''
      stage: V2
      tests: ["gpio_stress_all"]
    }
    {
      name: straps_data
      desc: '''Verify the straps data/valid ouput expected values based on the strap_en and gpio_i inputs:
      - Drive gpio_i input with random values.
      - Set strap_en high for at least one clock cycle.
      - Read the registers hw_straps_data_in and hw_straps_data_in_valid.
      - Check the data read and sampled_straps_o in the scoreboard.
      - Drive gpio_o and check that has no impact on straps registers.
      - Apply a reset and ensure the strap registers are cleared.
      - Read straps registers after reset.
      - Iterate few times through the same flow again with new random values. Several iterations
        will be done using the stress_all virtual sequence.
      '''
      stage: V3
      tests: ["gpio_rand_straps"]
    }
  ]
}
