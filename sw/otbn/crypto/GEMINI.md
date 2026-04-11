# OpenTitan OTBN Crypto Assembly Context

You are assisting in writing and auditing **OTBN (OpenTitan Big Number)** assembly code. This is a specialized environment for high-security asymmetric cryptography (RSA, ECC, etc.).

## 1. Architecture Overview
- **Word Size:** 256 bits.
- **Registers:** 
  - **`w0`–`w31`**: 256-bit Wide registers for big-number arithmetic.
  - **`x0`–`x31`**: 32-bit General-purpose registers for control flow and pointers (RISC-V-like).
- **DMEM:** Data memory is 32-bit word addressable but optimized for 256-bit loads (`bn.lid`) and stores (`bn.sid`).

## 2. Security & Hardening Requirements (Non-Negotiable)
- **Constant Time:** Every branch and instruction sequence must execute in the same number of cycles regardless of the secret data value.
- **Secret Sharing:** Private keys (like $d$) and secret scalars (like $k$) must be handled in two shares ($share_0, share_1$) where $Secret = (share_0 + share_1) \pmod n$.
- **Register Randomization:** Use the `URND` register to randomize unused registers and flags to mitigate side-channel leakage.
- **Fault Injection (FI) Countermeasures:** 
  - After point multiplication, verify the result is on the curve using `isoncurve`.
  - Use `trigger_fault_if_fg0_not_z` or similar logic to abort if integrity checks fail.

## 3. Instruction Patterns
- **Modular Arithmetic:** Use `bn.addm`, `bn.subm`. The modulus must be loaded into the `MOD` WSR (Work-group Specific Register) first using `bn.wsrw`.
- **Memory Alignment:** All `.bss` and `.data` labels in DMEM must be aligned to 32 bytes (`.balign 32`).
- **Loading Data:** Use `la` to load labels into X-registers, then `bn.lid` to bring data into W-registers.

## 4. Documentation Standard
Every subroutine must include a header specifying:
- **Parameters:** Which DMEM locations or registers hold inputs.
- **Returns:** Where the output is stored.
- **Clobbered Registers:** A complete list of all `w`, `x`, and `FG` (flag groups) modified.
- **Time Complexity:** Explicitly state if the routine is constant-time.

## 5. Build System
- **`otbn_library`:** For reusable components (e.g., modular inversion, Montgomery multiplication).
- **`otbn_binary`:** For top-level "apps" that the Ibex processor will load and run.
