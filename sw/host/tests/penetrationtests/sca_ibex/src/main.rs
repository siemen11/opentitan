// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use std::fs;
use std::time::Duration;

use serde::Deserialize;

use pentest_commands::sca_ibex_commands::IbexScaSubcommand;

use pentest_commands::commands::PenetrationtestCommand;

use opentitanlib::app::TransportWrapper;
use opentitanlib::execute_test;
use opentitanlib::io::uart::Uart;
use opentitanlib::test_utils::init::InitializeTest;
use opentitanlib::test_utils::rpc::{ConsoleRecv, ConsoleSend};
use opentitanlib::uart::console::UartConsole;

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    init: InitializeTest,

    // Console receive timeout.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    timeout: Duration,

    #[arg(long, num_args = 1..)]
    sca_ibex_json: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ScaIbexTestCase {
    test_case_id: usize,
    command: String,
    #[serde(default)]
    input: String,
    expected_output: String,
}

fn filter_response(response: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    let mut map: serde_json::Map<String, serde_json::Value> = response.as_object().unwrap().clone();
    // Device ID is different for each device.
    map.remove("device_id");
    return map;
}

fn run_sca_ibex_testcase(
    test_case: &ScaIbexTestCase,
    opts: &Opts,
    uart: &dyn Uart,
    fail_counter: &mut u32,
) -> Result<()> {
    log::info!(
        "test case: {}, test: {}",
        test_case.test_case_id,
        test_case.command
    );
    PenetrationtestCommand::IbexSca.send(uart)?;

    // Send test subcommand.
    match test_case.command.as_str() {
        "Init" => IbexScaSubcommand::Init,
        "KeySideloading" => IbexScaSubcommand::KeySideloading,
        "RFRead" => IbexScaSubcommand::RFRead,
        "RFReadBatchFvsr" => IbexScaSubcommand::RFReadBatchFvsr,
        "RFReadBatchRandom" => IbexScaSubcommand::RFReadBatchRandom,
        "RFWrite" => IbexScaSubcommand::RFWrite,
        "RFWriteBatchFvsr" => IbexScaSubcommand::RFWriteBatchFvsr,
        "RFWriteBatchRandom" => IbexScaSubcommand::RFWriteBatchRandom,
        "TLRead" => IbexScaSubcommand::TLRead,
        "TLReadBatchFvsr" => IbexScaSubcommand::TLReadBatchFvsr,
        "TLReadBatchFvsrFixAddress" => IbexScaSubcommand::TLReadBatchFvsrFixAddress,
        "TLReadBatchRandom" => IbexScaSubcommand::TLReadBatchRandom,
        "TLReadBatchRandomFixAddress" => IbexScaSubcommand::TLReadBatchRandomFixAddress,
        "TLWrite" => IbexScaSubcommand::TLWrite,
        "TLWriteBatchFvsr" => IbexScaSubcommand::TLWriteBatchFvsr,
        "TLWriteBatchFvsrFixAddress" => IbexScaSubcommand::TLWriteBatchFvsrFixAddress,
        "TLWriteBatchRandom" => IbexScaSubcommand::TLWriteBatchRandom,
        "TLWriteBatchRandomFixAddress" => IbexScaSubcommand::TLWriteBatchRandomFixAddress,
        _ => panic!("Unsupported Ibex SCA subcommand"),
    }
    .send(uart)?;

    // Check if we need to send an input.
    if test_case.input != "" {
        let input: serde_json::Value = serde_json::from_str(test_case.input.as_str()).unwrap();
        input.send(uart)?;
    }

    // Get test output & filter.
    let output = serde_json::Value::recv(uart, opts.timeout, false)?;
    let output_received = filter_response(output.clone());

    // Filter expected output.
    let exp_output: serde_json::Value =
        serde_json::from_str(test_case.expected_output.as_str()).unwrap();
    let output_expected = filter_response(exp_output.clone());

    // Check received with expected output.
    if output_expected != output_received {
        log::info!(
            "FAILED {} test #{}: expected = '{}', actual = '{}'",
            test_case.command,
            test_case.test_case_id,
            exp_output,
            output
        );
        *fail_counter += 1;
    }

    Ok(())
}

fn test_sca_ibex(opts: &Opts, transport: &TransportWrapper) -> Result<()> {
    let uart = transport.uart("console")?;
    uart.set_flow_control(true)?;
    let _ = UartConsole::wait_for(&*uart, r"Running [^\r\n]*", opts.timeout)?;

    let mut test_counter = 0u32;
    let mut fail_counter = 0u32;
    let test_vector_files = &opts.sca_ibex_json;
    for file in test_vector_files {
        let raw_json = fs::read_to_string(file)?;
        let sca_ibex_tests: Vec<ScaIbexTestCase> = serde_json::from_str(&raw_json)?;
        for sca_ibex_test in &sca_ibex_tests {
            test_counter += 1;
            log::info!("Test counter: {}", test_counter);
            run_sca_ibex_testcase(sca_ibex_test, opts, &*uart, &mut fail_counter)?;
        }
    }
    assert_eq!(
        0, fail_counter,
        "Failed {} out of {} tests.",
        fail_counter, test_counter
    );
    Ok(())
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    opts.init.init_logging();

    let transport = opts.init.init_target()?;
    execute_test!(test_sca_ibex, &opts, &transport);
    Ok(())
}
