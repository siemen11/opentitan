/* Copyright lowRISC contributors (OpenTitan project). */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */
/*
    OBTN.INSN.CARRY_FLAG SCA Test
*/
.section .text.start

    /* w0 & w1 are random, w2 contains the value big_num. */
    bn.wsrr w0, URND
    bn.wsrr w1, URND
    li      x2, 2
    la      x1, big_num
    bn.lid  x2, 0x00(x1)

    loopi 10, 1
      nop
    
    /* Add with carry: big_num = big_num + big_num. */
    bn.addc w2, w2, w2

    loopi 10, 1
      nop
    
    /* If carry was set, store random number into w0. If not, store big_num.  */
    bn.sel  w0, w1, w2, C

    loopi 10, 1
      nop

    /* Write w0 back to DEM. */
    li      x2, 0
    la      x1, big_num_out
    bn.sid  x2, 0x000(x1)

    ecall

.data
    .globl big_num
    .balign 32
    big_num:
        .zero 32

    .globl big_num_out
    .balign 32
    big_num_out:
        .zero 32
