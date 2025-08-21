# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from target.communication.fi_otp_commands import OTFIOtp
from target.targets import Target, TargetConfig
from target.communication import common_library


def char_vendor_test(target, iterations):
    target.reset_target()
    # Clear the output from the reset
    target.dump_all()

    otpfi = OTFIOtp(target)
    # Initialize our chip and catch its output
    device_id, sensors, alerts, owner_page, boot_log, boot_measurements, version = (
        otpfi.init(alert_config=common_library.default_fpga_friendly_alert_config)
    )
    for _ in range(iterations):
        otpfi.otp_fi_vendor_test()
        response = target.read_response()
    return response


def char_owner_sw_cfg(target, iterations):
    target.reset_target()
    # Clear the output from the reset
    target.dump_all()

    otpfi = OTFIOtp(target)
    # Initialize our chip and catch its output
    device_id, sensors, alerts, owner_page, boot_log, boot_measurements, version = (
        otpfi.init(alert_config=common_library.default_fpga_friendly_alert_config)
    )
    for _ in range(iterations):
        otpfi.otp_fi_owner_sw_cfg()
        response = target.read_response()
    return response


def char_hw_cfg(target, iterations):
    target.reset_target()
    # Clear the output from the reset
    target.dump_all()

    otpfi = OTFIOtp(target)
    # Initialize our chip and catch its output
    device_id, sensors, alerts, owner_page, boot_log, boot_measurements, version = (
        otpfi.init(alert_config=common_library.default_fpga_friendly_alert_config)
    )
    for _ in range(iterations):
        otpfi.otp_fi_hw_cfg()
        response = target.read_response()
    return response


def char_life_cycle(target, iterations):
    target.reset_target()
    # Clear the output from the reset
    target.dump_all()

    otpfi = OTFIOtp(target)
    # Initialize our chip and catch its output
    device_id, sensors, alerts, owner_page, boot_log, boot_measurements, version = (
        otpfi.init(alert_config=common_library.default_fpga_friendly_alert_config)
    )
    for _ in range(iterations):
        otpfi.otp_fi_life_cycle()
        response = target.read_response()
    return response
