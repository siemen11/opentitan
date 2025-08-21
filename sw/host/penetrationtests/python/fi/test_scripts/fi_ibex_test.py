# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from sw.host.penetrationtests.python.fi.host_scripts import fi_ibex_functions
from sw.host.penetrationtests.python.fi.communication.fi_ibex_commands import OTFIIbex
from python.runfiles import Runfiles
from sw.host.penetrationtests.python.util import targets
from sw.host.penetrationtests.python.util import utils
from sw.host.penetrationtests.python.util import common_library
import os
import json
import unittest

opentitantool_path = ""
iterations = 3
ignored_keys_set = set(
    ["registers", "registers_test_1", "registers_test_2", "registers_test_3"]
)

target = None


class IbexFiTest(unittest.TestCase):

    def test_init(self):
        ibexfi = OTFIIbex(target)
        device_id, sensors, alerts, owner_page, boot_log, boot_measurements, version = (
            ibexfi.init(alert_config=common_library.default_fpga_friendly_alert_config)
        )
        device_id_json = json.loads(device_id)
        sensors_json = json.loads(sensors)
        alerts_json = json.loads(alerts)
        owner_page_json = json.loads(owner_page)
        boot_log_json = json.loads(boot_log)
        boot_measurements_json = json.loads(boot_measurements)

        expected_device_id_keys = {
            "device_id",
            "rom_digest",
            "icache_en",
            "dummy_instr_en",
            "clock_jitter_locked",
            "clock_jitter_en",
            "sram_main_readback_locked",
            "sram_main_readback_en",
            "sram_ret_readback_locked",
            "sram_ret_readback_en",
            "data_ind_timing_en",
        }
        actual_device_id_keys = set(device_id_json.keys())

        self.assertEqual(
            expected_device_id_keys,
            actual_device_id_keys,
            "device_id keys do not match",
        )

        expected_sensors_keys = {"sensor_ctrl_en", "sensor_ctrl_fatal"}
        actual_sensors_keys = set(sensors_json.keys())

        self.assertEqual(
            expected_sensors_keys, actual_sensors_keys, "sensor keys do not match"
        )

        expected_alerts_keys = {
            "alert_classes",
            "enabled_alerts",
            "enabled_classes",
            "accumulation_thresholds",
            "duration_cycles",
            "escalation_signals_en",
            "escalation_signals_map",
        }
        actual_alerts_keys = set(alerts_json.keys())

        self.assertEqual(
            expected_alerts_keys, actual_alerts_keys, "alert keys do not match"
        )

        expected_owner_page_keys = {
            "config_version",
            "sram_exec_mode",
            "ownership_key_alg",
            "update_mode",
            "min_security_version_bl0",
            "lock_constraint",
        }
        actual_owner_page_keys = set(owner_page_json.keys())

        self.assertEqual(
            expected_owner_page_keys,
            actual_owner_page_keys,
            "owner_page keys do not match",
        )

        expected_boot_log_keys = {
            "digest",
            "identifier",
            "scm_revision_low",
            "scm_revision_high",
            "rom_ext_slot",
            "rom_ext_major",
            "rom_ext_minor",
            "rom_ext_size",
            "bl0_slot",
            "ownership_state",
            "ownership_transfers",
            "rom_ext_min_sec_ver",
            "bl0_min_sec_ver",
            "primary_bl0_slot",
            "retention_ram_initialized",
        }
        actual_boot_log_keys = set(boot_log_json.keys())

        self.assertEqual(
            expected_boot_log_keys, actual_boot_log_keys, "boot_log keys do not match"
        )

        expected_boot_measurements_keys = {"bl0", "rom_ext"}
        actual_boot_measurements_keys = set(boot_measurements_json.keys())

        self.assertEqual(
            expected_boot_measurements_keys,
            actual_boot_measurements_keys,
            "boot_measurements keys do not match",
        )

        self.assertIn("PENTEST", version)

    def test_char_addi_single_beq(self):
        actual_result = fi_ibex_functions.char_addi_single_beq(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty":[ \
                false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_addi_single_beq_neg(self):
        actual_result = fi_ibex_functions.char_addi_single_beq_neg(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_addi_single_bne(self):
        actual_result = fi_ibex_functions.char_addi_single_bne(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_addi_single_bne_neg(self):
        actual_result = fi_ibex_functions.char_addi_single_bne_neg(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_combi(self):
        actual_result = fi_ibex_functions.char_combi(target, iterations)
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty_test_1": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data_test_1":[0,0,0,0,0,0,0,0,0,0,0,0,0],"result_test_2":13, \
                "result_test_3":15,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_conditional_branch_beq(self):
        actual_result = fi_ibex_functions.char_conditional_branch_beq(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result1":175,"result2":239,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_conditional_branch_bge(self):
        actual_result = fi_ibex_functions.char_conditional_branch_bge(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result1":175,"result2":239,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_conditional_branch_bgeu_test(self):
        actual_result = fi_ibex_functions.char_conditional_branch_bgeu(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result1":175,"result2":239,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_conditional_branch_blt(self):
        actual_result = fi_ibex_functions.char_conditional_branch_blt(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result1":239,"result2":175,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_conditional_branch_bltu(self):
        actual_result = fi_ibex_functions.char_conditional_branch_bltu(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result1":239,"result2":175,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_conditional_branch_bne(self):
        actual_result = fi_ibex_functions.char_conditional_branch_bne(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result1":175,"result2":175,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_csr_read(self):
        actual_result = fi_ibex_functions.char_csr_read(target, iterations)
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
            [false,false,false,false,false,false,false,false,false,false,false,false,false], \
            "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_csr_write(self):
        actual_result = fi_ibex_functions.char_csr_write(target, iterations)
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result":0,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_csr_combi(self):
        ref_values = [
            1,
            5,
            33,
            101,
            3,
            5,
            39321,
            6,
            5138,
            50115,
            39321,
            38502,
            39321,
            39321,
            1,
            2,
            3,
        ]
        actual_result = fi_ibex_functions.char_csr_combi(
            target, trigger=0, ref_values=ref_values, iterations=iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"output":[1,5,33,101,3,5,39321,6,5138,50115,39321,38502,39321,39321,1,2,3], \
                "data_faulty": [false,false,false,false,false,false,false,false,false,false, \
                false,false,false,false,false,false,false],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

        ref_values = [
            2,
            3,
            16641,
            4,
            5,
            6,
            38553,
            7,
            5137,
            256,
            26214,
            26214,
            26214,
            5,
            2,
            3,
            4,
        ]
        actual_result = fi_ibex_functions.char_csr_combi(
            target, trigger=0, ref_values=ref_values, iterations=iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"output":[2,3,16641,4,5,6,38553,7,5137,256,26214,26214,26214,5,2,3,4], \
                "data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false,\
                false,false,false,false],"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_flash_read(self):
        for flash_region in range(2, 10):
            actual_result = fi_ibex_functions.char_flash_read(
                target, flash_region=flash_region, iterations=iterations
            )
            actual_result_json = json.loads(actual_result)
            expected_result_json = json.loads(
                '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                    "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                    "ast_alerts":[0,0]}'
            )
            if "success" not in actual_result_json:
                utils.compare_json_data(
                    actual_result_json, expected_result_json, ignored_keys_set
                )

    def test_char_flash_write(self):
        for flash_region in range(2, 10):
            actual_result = fi_ibex_functions.char_flash_write(
                target, flash_region=flash_region, iterations=iterations
            )
            actual_result_json = json.loads(actual_result)
            expected_result_json = json.loads(
                '{"result":0,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
            )
            if "success" not in actual_result_json:
                utils.compare_json_data(
                    actual_result_json, expected_result_json, ignored_keys_set
                )

    def test_char_mem_op_loop(self):
        actual_result = fi_ibex_functions.char_mem_op_loop(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result":[10000,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_register_file(self):
        actual_result = fi_ibex_functions.char_register_file(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_register_file_read(self):
        actual_result = fi_ibex_functions.char_register_file_read(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_reg_op_loop(self):
        actual_result = fi_ibex_functions.char_reg_op_loop(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_single_beq(self):
        actual_result = fi_ibex_functions.char_single_beq(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_single_bne(self):
        actual_result = fi_ibex_functions.char_single_bne(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_sram_read(self):
        actual_result = fi_ibex_functions.char_sram_read(target, iterations)
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_sram_read_ret(self):
        actual_result = fi_ibex_functions.char_sram_read_ret(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"sram_err_status":56, "data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_sram_static(self):
        actual_result = fi_ibex_functions.char_sram_static(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"addresses":[0,0,0,0,0,0,0,0,0,0,0,0,0],"data":[0,0,0,0,0,0,0,0,0,0,0,0,0], \
                "err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_sram_write(self):
        actual_result = fi_ibex_functions.char_sram_write(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"memory":[464367618,2343432205,2779096485,2880154539,2881141438,2880293630, \
                3131746989,3134333474,3148725999,3200171710,3203386062,3221229823,3405697037, \
                3405709037,3435973836,3452816845,219540062,3735883980,3735928559,3735931646, \
                3735929054,3735943697,3735941133,3741239533,3735936685,3490524077,3958107115, \
                4208909997,4261281277,4276215469,4277009102,4277075694,464367618,2343432205, \
                2779096485,2880154539,2881141438,2880293630,3131746989,3134333474,3148725999, \
                3200171710,3203386062,3221229823,3405697037,3405709037,3435973836,3452816845, \
                219540062,3735883980,3735928559,3735931646,3735929054,3735943697,3735941133, \
                3741239533,3735936685,3490524077,3958107115,4208909997,4261281277,4276215469, \
                4277009102,4277075694],"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_sram_write_read(self):
        actual_result = fi_ibex_functions.char_sram_write_read(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"data_faulty": \
                [false,false,false,false,false,false,false,false,false,false,false,false,false], \
                "data":[0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
                "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_sram_write_read_alt(self):
        actual_result = fi_ibex_functions.char_sram_write_read_alt(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"memory":[2880293630,3131746989,3134333474,2880293630,3131746989,3134333474, \
            2880293630,3131746989,3134333474,2880293630,3131746989,3134333474,2880293630, \
            3131746989,3134333474,2880293630,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"err_status":0,"alerts":[0,0,0], \
            "ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_sram_write_static_unrolled(self):
        actual_result = fi_ibex_functions.char_sram_write_static_unrolled(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"memory":[464367618,464367618,464367618,464367618,464367618,464367618,464367618, \
            464367618,464367618,464367618,464367618,464367618,464367618,464367618,464367618, \
            464367618,464367618,464367618,464367618,464367618,464367618,464367618,464367618, \
            464367618,464367618,464367618,464367618,464367618,464367618,464367618,464367618, \
            464367618,464367618,464367618,464367618,464367618,464367618,464367618,464367618, \
            464367618,464367618,464367618,464367618,464367618,464367618,464367618,464367618, \
            464367618,464367618,464367618,464367618,464367618,464367618,464367618,464367618, \
            464367618,464367618,464367618,464367618,464367618,464367618,464367618,464367618, \
            464367618],"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_unconditional_branch(self):
        actual_result = fi_ibex_functions.char_unconditional_branch(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result":30,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_unconditional_branch_nop(self):
        actual_result = fi_ibex_functions.char_unconditional_branch_nop(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result":0,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_unrolled_mem_op_loop(self):
        actual_result = fi_ibex_functions.char_unrolled_mem_op_loop(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result":10000,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_unrolled_reg_op_loop(self):
        actual_result = fi_ibex_functions.char_unrolled_reg_op_loop(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result":10000,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_unrolled_reg_op_loop_chain(self):
        actual_result = fi_ibex_functions.char_unrolled_reg_op_loop_chain(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result":[60,55,56,57,58,59,0,0,0,0,0,0],"err_status":0, \
                "alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_otp_data_read(self):
        actual_result = fi_ibex_functions.char_otp_data_read(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result": 0,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_otp_read_lock(self):
        actual_result = fi_ibex_functions.char_otp_read_lock(
            target, iterations
        )
        actual_result_json = json.loads(actual_result)
        expected_result_json = json.loads(
            '{"result": 5,"err_status":0,"alerts":[0,0,0],"ast_alerts":[0,0]}'
        )
        utils.compare_json_data(
            actual_result_json, expected_result_json, ignored_keys_set
        )

    def test_char_addi_single_beq_cm(self):
        actual_result, status = fi_ibex_functions.char_addi_single_beq_cm(
            target
        )
        self.assertIn("FAULT", actual_result)

    def test_char_addi_single_beq_cm2(self):
        actual_result, status = fi_ibex_functions.char_addi_single_beq_cm2(
            target
        )
        self.assertIn("FAULT", actual_result)

    def test_char_hardened_check_eq_complement_branch(self):
        actual_result, status = (
            fi_ibex_functions.char_hardened_check_eq_complement_branch(
                target
            )
        )
        self.assertIn("FAULT", actual_result)

    def test_char_hardened_check_eq_unimp(self):
        actual_result, status = fi_ibex_functions.char_hardened_check_eq_unimp(
            target
        )
        self.assertIn("FAULT", actual_result)

    def test_char_hardened_check_eq_2_unimps(self):
        actual_result, status = fi_ibex_functions.char_hardened_check_eq_2_unimps(
            target
        )
        self.assertIn("FAULT", actual_result)

    def test_char_hardened_check_eq_3_unimps(self):
        actual_result, status = fi_ibex_functions.char_hardened_check_eq_3_unimps(
            target
        )
        self.assertIn("FAULT", actual_result)

    def test_char_hardened_check_eq_4_unimps(self):
        actual_result, status = fi_ibex_functions.char_hardened_check_eq_4_unimps(
            target
        )
        self.assertIn("FAULT", actual_result)

    def test_char_hardened_check_eq_5_unimps(self):
        actual_result, status = fi_ibex_functions.char_hardened_check_eq_5_unimps(
            target
        )
        self.assertIn("FAULT", actual_result)


if __name__ == "__main__":
    r = Runfiles.Create()
    opentitantool_path = r.Rlocation(
        "lowrisc_opentitan/sw/host/opentitantool/opentitantool"
    )

    target_name = os.environ.get("TEST_TARGET")
    delimiter = "_test_"
    _, _, firmware_target_name = target_name.partition(delimiter)
    firmware_path = r.Rlocation(
        f"lowrisc_opentitan/sw/device/tests/penetrationtests/firmware/{firmware_target_name}.img"
    )

    target_type = "chip"
    if "cw305" in firmware_target_name:
        target_type = "cw305"
    elif "cw310" in firmware_target_name:
        target_type = "cw310"

    target_cfg = targets.TargetConfig(target_type, firmware_path, opentitantool=opentitantool_path)
    target = targets.Target(target_cfg)

    unittest.main()
