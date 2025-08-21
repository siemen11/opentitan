# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from sw.host.penetrationtests.python.sca.communication.sca_hmac_commands import OTHMAC
from sw.host.penetrationtests.python.sca.communication.sca_prng_commands import OTPRNG
from sw.host.penetrationtests.python.util import targets


def char_hmac_single(target, iterations, trigger, key, text):
    target.reset_target()
    # Clear the output from the reset
    target.dump_all()

    hmacsca = OTHMAC(target)
    # Initialize our chip and catch its output
    device_id, owner_page, boot_log, boot_measurements, version = hmacsca.init()

    for _ in range(iterations):
        hmacsca.single(text, key, trigger)
        response = target.read_response()
    return response


def char_hmac_daisy_chain(target, iterations, num_segments, trigger, key, text):
    target.reset_target()
    # Clear the output from the reset
    target.dump_all()

    hmacsca = OTHMAC(target)
    # Initialize our chip and catch its output
    device_id, owner_page, boot_log, boot_measurements, version = hmacsca.init()

    for _ in range(iterations):
        hmacsca.daisy_chain(text, key, num_segments, trigger)
        response = target.read_response()
    return response


def char_hmac_random_batch(target, iterations, num_segments, trigger):
    target.reset_target()
    # Clear the output from the reset
    target.dump_all()

    hmacsca = OTHMAC(target)
    # Initialize our chip and catch its output
    device_id, owner_page, boot_log, boot_measurements, version = hmacsca.init()

    # Set the internal prng
    ot_prng = OTPRNG(target=target)
    ot_prng.seed_prng([1, 0, 0, 0])

    for _ in range(iterations):
        hmacsca.random_batch(num_segments, trigger)
        response = target.read_response()
    return response


def char_hmac_fvsr_batch(target, iterations, num_segments, trigger, key):
    target.reset_target()
    # Clear the output from the reset
    target.dump_all()

    hmacsca = OTHMAC(target)
    # Initialize our chip and catch its output
    device_id, owner_page, boot_log, boot_measurements, version = hmacsca.init()

    # Set the internal prng
    ot_prng = OTPRNG(target=target)
    ot_prng.seed_prng([1, 0, 0, 0])

    for _ in range(iterations):
        hmacsca.fvsr_batch(key, num_segments, trigger)
        response = target.read_response()
    return response
