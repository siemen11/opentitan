// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_IBEX_FI_COMMANDS_H_
#define OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_IBEX_FI_COMMANDS_H_
#include "sw/device/lib/ujson/ujson_derive.h"
#ifdef __cplusplus
extern "C" {
#endif

// clang-format off

#define IBEXFI_SUBCOMMAND(_, value) \
    value(_, AddressTranslation) \
    value(_, AddressTranslationCfg) \
    value(_, CharCondBranchBeq) \
    value(_, CharCondBranchBge) \
    value(_, CharCondBranchBgeu) \
    value(_, CharCondBranchBlt) \
    value(_, CharCondBranchBltu) \
    value(_, CharCondBranchBne) \
    value(_, CharCsrRead) \
    value(_, CharCsrWrite) \
    value(_, CharFlashRead) \
    value(_, CharFlashWrite) \
    value(_, CharHardenedCheckComplementBranch) \
    value(_, CharHardenedCheckUnimp) \
    value(_, CharHardenedCheck2Unimps) \
    value(_, CharHardenedCheck3Unimps) \
    value(_, CharHardenedCheck4Unimps) \
    value(_, CharHardenedCheck5Unimps) \
    value(_, CharMemOpLoop) \
    value(_, CharRegisterFile) \
    value(_, CharRegisterFileRead) \
    value(_, CharRegOpLoop) \
    value(_, CharSramRead) \
    value(_, CharSramStatic) \
    value(_, CharSramWrite) \
    value(_, CharSramWriteRead) \
    value(_, CharSramWriteStaticUnrolled) \
    value(_, CharUncondBranch) \
    value(_, CharUncondBranchNop) \
    value(_, CharUnrolledMemOpLoop) \
    value(_, CharUnrolledRegOpLoop) \
    value(_, CharUnrolledRegOpLoopChain) \
    value(_, Init) \
    value(_, OtpDataRead) \
    value(_, OtpReadLock) \
    value(_, OtpWriteLock)
UJSON_SERDE_ENUM(IbexFiSubcommand, ibex_fi_subcommand_t, IBEXFI_SUBCOMMAND);

#define IBEXFI_TEST_RESULT(field, string) \
    field(result, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2)
UJSON_SERDE_STRUCT(IbexFiTestResult, ibex_fi_test_result_t, IBEXFI_TEST_RESULT);

#define IBEXFI_TEST_RESULT_SRAM(field, string) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2) \
    field(memory, uint32_t, 64) \
    field(registers, uint32_t, 32)
UJSON_SERDE_STRUCT(IbexFiTestResultSram, ibex_fi_test_result_sram_t, IBEXFI_TEST_RESULT_SRAM);

#define IBEXFI_TEST_RESULT_SRAM_32(field, string) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2) \
    field(memory, uint32_t, 32) \
    field(registers, uint32_t, 32)
UJSON_SERDE_STRUCT(IbexFiTestResultSram32, ibex_fi_test_result_sram_32_t, IBEXFI_TEST_RESULT_SRAM_32);

#define IBEXFI_TEST_RESULT_REGISTERS(field, string) \
    field(result, uint32_t) \
    field(registers, uint32_t, 32) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2) 
UJSON_SERDE_STRUCT(IbexFiTestResultRegisters, ibex_fi_test_result_registers_t, IBEXFI_TEST_RESULT_REGISTERS);

#define IBEXFI_TEST_RESULT_MULT(field, string) \
    field(result1, uint32_t) \
    field(result2, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2)
UJSON_SERDE_STRUCT(IbexFiTestResultMult, ibex_fi_test_result_mult_t, IBEXFI_TEST_RESULT_MULT);

#define IBEXFI_LOOP_COUNTER_OUTPUT(field, string) \
    field(loop_counter, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2)
UJSON_SERDE_STRUCT(IbexFiLoopCounterOutput, ibex_fi_loop_counter_t, IBEXFI_LOOP_COUNTER_OUTPUT);

#define IBEXFI_LOOP_COUNTER_REG_OUTPUT(field, string) \
    field(loop_counter, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2) \
    field(registers, uint32_t, 32)
UJSON_SERDE_STRUCT(IbexFiLoopCounterRegOutput, ibex_fi_loop_counter_reg_t, IBEXFI_LOOP_COUNTER_REG_OUTPUT);

#define IBEXFI_LOOP_COUNTER_MIRRORED_OUTPUT(field, string) \
    field(loop_counter1, uint32_t) \
    field(loop_counter2, uint32_t) \
    field(err_status, uint32_t) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2) \
    field(registers, uint32_t, 32)
UJSON_SERDE_STRUCT(IbexFiLoopCounterMirroredOutput, ibex_fi_loop_counter_mirrored_t, IBEXFI_LOOP_COUNTER_MIRRORED_OUTPUT);

#define IBEXFI_FAULTY_ADDRESSES_DATA(field, string) \
    field(err_status, uint32_t) \
    field(addresses, uint32_t, 13) \
    field(data, uint32_t, 13) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2)
UJSON_SERDE_STRUCT(IbexFiFaultyAddressesData, ibex_fi_faulty_addresses_data_t, IBEXFI_FAULTY_ADDRESSES_DATA);

#define IBEXFI_FAULTY_REG_DATA(field, string) \
    field(err_status, uint32_t) \
    field(registers, uint32_t, 32) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2)
UJSON_SERDE_STRUCT(IbexFiFaultyRegData, ibex_fi_faulty_reg_data_t, IBEXFI_FAULTY_REG_DATA);

#define IBEXFI_FAULTY_ADDRESSES(field, string) \
    field(err_status, uint32_t) \
    field(addresses, uint32_t, 8) \
    field(alerts, uint32_t, 3) \
    field(ast_alerts, uint32_t, 2)
UJSON_SERDE_STRUCT(IbexFiFaultyAddresses, ibex_fi_faulty_addresses_t, IBEXFI_FAULTY_ADDRESSES);

// clang-format on

#ifdef __cplusplus
}
#endif
#endif  // OPENTITAN_SW_DEVICE_TESTS_PENETRATIONTESTS_JSON_IBEX_FI_COMMANDS_H_
