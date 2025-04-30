// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use std::fs;
use std::time::Duration;

use serde::Deserialize;

use pentest_commands::fi_otbn_commands::OtbnFiSubcommand;

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
    fi_otbn_json: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FiOtbnTestCase {
    test_case_id: usize,
    command: String,
    #[serde(default)]
    input: String,
    expected_output: String,
}

fn filter_response(response: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    let mut map: serde_json::Map<String, serde_json::Value> = response.as_object().unwrap().clone();
    // Depending on the device configuration, alerts can sometimes fire.
    map.remove("alerts");
    map.remove("ast_alerts");
    map.remove("err_status");
    // Device ID is different for each device.
    map.remove("device_id");
    // OTBN instruction counter should be const.
    map.remove("insn_cnt");
    // Filter as the CharBnWsrr returns random data from OTBN.
    map.remove("data");
    return map;
}

fn run_fi_otbn_testcase(
    test_case: &FiOtbnTestCase,
    opts: &Opts,
    uart: &dyn Uart,
    fail_counter: &mut u32,
) -> Result<()> {
    log::info!(
        "test case: {}, test: {}",
        test_case.test_case_id,
        test_case.command
    );
    PenetrationtestCommand::OtbnFi.send(uart)?;

    // Send test subcommand.
    match test_case.command.as_str() {
        "CharBeq" => OtbnFiSubcommand::CharBeq,
        "CharBnRshi" => OtbnFiSubcommand::CharBnRshi,
        "CharBnSel" => OtbnFiSubcommand::CharBnSel,
        "CharBnWsrr" => OtbnFiSubcommand::CharBnWsrr,
        "CharBne" => OtbnFiSubcommand::CharBne,
        "CharDmemAccess" => OtbnFiSubcommand::CharDmemAccess,
        "CharDmemWrite" => OtbnFiSubcommand::CharDmemWrite,
        "CharHardwareDmemOpLoop" => OtbnFiSubcommand::CharHardwareDmemOpLoop,
        "CharHardwareRegOpLoop" => OtbnFiSubcommand::CharHardwareRegOpLoop,
        "CharJal" => OtbnFiSubcommand::CharJal,
        "CharLw" => OtbnFiSubcommand::CharLw,
        "CharMem" => OtbnFiSubcommand::CharMem,
        "CharRF" => OtbnFiSubcommand::CharRF,
        "CharUnrolledDmemOpLoop" => OtbnFiSubcommand::CharUnrolledDmemOpLoop,
        "CharUnrolledRegOpLoop" => OtbnFiSubcommand::CharUnrolledRegOpLoop,
        "Init" => OtbnFiSubcommand::Init,
        "InitKeyMgr" => OtbnFiSubcommand::InitKeyMgr,
        "KeySideload" => OtbnFiSubcommand::KeySideload,
        "LoadIntegrity" => OtbnFiSubcommand::LoadIntegrity,
        "PC" => OtbnFiSubcommand::PC,
        _ => panic!("Unsupported OTBN FI subcommand"),
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

fn test_fi_otbn(opts: &Opts, transport: &TransportWrapper) -> Result<()> {
    let uart = transport.uart("console")?;
    uart.set_flow_control(true)?;
    let _ = UartConsole::wait_for(&*uart, r"Running [^\r\n]*", opts.timeout)?;

    let mut test_counter = 0u32;
    let mut fail_counter = 0u32;
    let test_vector_files = &opts.fi_otbn_json;
    // File wird noch nicht richtig geparsed.
    for file in test_vector_files {
        let raw_json = fs::read_to_string(file)?;
        let fi_otbn_tests: Vec<FiOtbnTestCase> = serde_json::from_str(&raw_json)?;
        for fi_otbn_test in &fi_otbn_tests {
            test_counter += 1;
            log::info!("Test counter: {}", test_counter);
            run_fi_otbn_testcase(fi_otbn_test, opts, &*uart, &mut fail_counter)?;
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
    execute_test!(test_fi_otbn, &opts, &transport);
    Ok(())
}
