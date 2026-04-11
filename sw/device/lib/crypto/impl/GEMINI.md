# OpenTitan Crypto Implementation (impl) Context

You are assisting in the core implementation of cryptographic algorithms. This layer bridges the top-level API and the hardware drivers.

## 1. Status & Error Handling
- **Return Type:** Always use `status_t`.
- **Flow Control:** Use `HARDENED_TRY()` for calling functions that return `status_t`.
- **Exit Pattern:** Use `return otcrypto_eval_exit(...)` for the final return of public API functions to ensure hardening checks are finalized.
- **Module ID:** Every file must define a unique `MODULE_ID`. (e.g., AES uses `aes`, GHASH uses `gha`).

## 2. Key Blinding & Integrity
- **Blinded Keys:** Most keys are stored in two shares (`share0`, `share1`). Never combine them in a way that leaks the raw key to the bus.
- **Integrity Checks:** Always call `integrity_blinded_key_check` before using a key.
- **Re-masking:** For software-backed keys, use `keyblob_remask` to refresh the blinding before use.

## 3. FI-Resistance (Fault Injection)
- **Loop Hardening:** 
    - Use `launder32()` for loop indices and critical decision variables.
    - After loops, use `HARDENED_CHECK_EQ` or `HARDENED_CHECK_LE` to verify the loop ran the expected number of iterations.
- **Redundant Computation:** For high-security levels, implement a "redundant" version of the operation (e.g., `ghash_update_redundant`) that computes the result twice and compares the state.
- **Enum Assertions:** Use `OT_ASSERT_ENUM_VALUE` to ensure top-level API enums match internal driver enums.

## 4. Memory Operations
- Use `randomized_bytecopy` instead of `memcpy` for sensitive data.
- Use `hardened_memshred` to wipe local blocks and buffers before they go out of scope.
