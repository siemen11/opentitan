// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::Parser;
use std::fs;
use std::time::Duration;

use serde::Deserialize;

use pentest_commands::fi_crypto_commands::CryptoFiSubcommand;

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
    fi_crypto_json: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FiCryptoTestCase {
    test_case_id: usize,
    command: String,
    #[serde(default)]
    input: String,
    #[serde(default)]
    mode: String,
    expected_output: String,
    #[serde(default)]
    expected_output2: String,
    #[serde(default)]
    expected_output3: String,
    #[serde(default)]
    expected_output4: String,
    // This is the TESTOS version, and is not checked
    #[serde(default)]
    expected_output5: String,
}

fn filter_response(response: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    let mut map: serde_json::Map<String, serde_json::Value> = response.as_object().unwrap().clone();
    // Depending on the device configuration, alerts can sometimes fire.
    map.remove("alerts");
    map.remove("ast_alerts");
    map.remove("err_status");
    // Device ID is different for each device.
    map.remove("device_id");
    // The following parameters are returned on init but are device dependent
    map.remove("config_version");
    map.remove("sram_exec_mode");
    map.remove("ownership_key_alg");
    map.remove("update_mode");
    map.remove("min_security_version_bl0");
    map.remove("lock_constraint");
    map.remove("digest");
    map.remove("identifier");
    map.remove("scm_revision_low");
    map.remove("scm_revision_high");
    map.remove("rom_ext_slot");
    map.remove("rom_ext_major");
    map.remove("rom_ext_minor");
    map.remove("rom_ext_size");
    map.remove("bl0_slot");
    map.remove("ownership_state");
    map.remove("ownership_transfers");
    map.remove("rom_ext_min_sec_ver");
    map.remove("bl0_min_sec_ver");
    map.remove("primary_bl0_slot");
    map.remove("retention_ram_initialized");
    map.remove("bl0");
    map.remove("rom_ext");
    // Filter the clock jitter enable/disable field as on A2 it is always enabled
    // when writing any value into the config register.
    map.remove("clock_jitter_en");
    // Shares use randomness which will differ
    map.remove("share0");
    map.remove("share1");
    return map;
}

fn run_fi_crypto_testcase(
    test_case: &FiCryptoTestCase,
    opts: &Opts,
    uart: &dyn Uart,
    fail_counter: &mut u32,
) -> Result<()> {
    log::info!(
        "test case: {}, test: {}",
        test_case.test_case_id,
        test_case.command
    );
    PenetrationtestCommand::CryptoFi.send(uart)?;

    // Send test subcommand.
    match test_case.command.as_str() {
        "Aes" => CryptoFiSubcommand::Aes,
        "Init" => CryptoFiSubcommand::Init,
        "Kmac" => CryptoFiSubcommand::Kmac,
        "KmacState" => CryptoFiSubcommand::KmacState,
        "Sha256" => CryptoFiSubcommand::Sha256,
        "ShadowRegAccess" => CryptoFiSubcommand::ShadowRegAccess,
        "ShadowRegRead" => CryptoFiSubcommand::ShadowRegRead,
        _ => panic!("Unsupported Crypto FI subcommand"),
    }
    .send(uart)?;

    // Check if we need to send an input.
    if test_case.input != "" {
        let input: serde_json::Value = serde_json::from_str(test_case.input.as_str()).unwrap();
        input.send(uart)?;
    }

    // Check if we need to send a mode.
    if test_case.mode != "" {
        let mode: serde_json::Value = serde_json::from_str(test_case.mode.as_str()).unwrap();
        mode.send(uart)?;
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

    if test_case.expected_output2 != "" {
        let exp_output2: serde_json::Value =
            serde_json::from_str(test_case.expected_output2.as_str()).unwrap();
        let output_expected2 = filter_response(exp_output2.clone());
        let output2 = serde_json::Value::recv(uart, opts.timeout, false)?;
        let output_received2 = filter_response(output2.clone());
        // Check received with the second expected output.
        if output_expected2 != output_received2 {
            log::info!(
                "FAILED {} test #{}: expected = '{}', actual = '{}'",
                test_case.command,
                test_case.test_case_id,
                exp_output2,
                output2
            );
            *fail_counter += 1;
        }
    }

    if test_case.expected_output3 != "" {
        let exp_output3: serde_json::Value =
            serde_json::from_str(test_case.expected_output3.as_str()).unwrap();
        let output_expected3 = filter_response(exp_output3.clone());
        let output3 = serde_json::Value::recv(uart, opts.timeout, false)?;
        let output_received3 = filter_response(output3.clone());
        // Check received with the second expected output.
        if output_expected3 != output_received3 {
            log::info!(
                "FAILED {} test #{}: expected = '{}', actual = '{}'",
                test_case.command,
                test_case.test_case_id,
                exp_output3,
                output3
            );
            *fail_counter += 1;
        }
    }

    if test_case.expected_output4 != "" {
        let exp_output4: serde_json::Value =
            serde_json::from_str(test_case.expected_output4.as_str()).unwrap();
        let output_expected4 = filter_response(exp_output4.clone());
        let output4 = serde_json::Value::recv(uart, opts.timeout, false)?;
        let output_received4 = filter_response(output4.clone());
        // Check received with the second expected output.
        if output_expected4 != output_received4 {
            log::info!(
                "FAILED {} test #{}: expected = '{}', actual = '{}'",
                test_case.command,
                test_case.test_case_id,
                exp_output4,
                output4
            );
            *fail_counter += 1;
        }
    }

    // The fifth response is just a string and not a json output
    // We read it but do not check it
    if test_case.expected_output5 != "" {
        serde_json::Value::recv(uart, opts.timeout, false)?;
    }

    Ok(())
}

fn test_fi_crypto(opts: &Opts, transport: &TransportWrapper) -> Result<()> {
    let uart = transport.uart("console")?;
    uart.set_flow_control(true)?;
    let _ = UartConsole::wait_for(&*uart, r"Running [^\r\n]*", opts.timeout)?;

    let mut test_counter = 0u32;
    let mut fail_counter = 0u32;
    let test_vector_files = &opts.fi_crypto_json;
    // File wird noch nicht richtig geparsed.
    for file in test_vector_files {
        let raw_json = fs::read_to_string(file)?;
        let fi_crypto_tests: Vec<FiCryptoTestCase> = serde_json::from_str(&raw_json)?;
        for fi_crypto_test in &fi_crypto_tests {
            test_counter += 1;
            log::info!("Test counter: {}", test_counter);
            run_fi_crypto_testcase(fi_crypto_test, opts, &*uart, &mut fail_counter)?;
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
    execute_test!(test_fi_crypto, &opts, &transport);
    Ok(())
}
