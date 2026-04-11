# OpenTitan Crypto Tests Context

You are assisting in writing and debugging device-level tests for the OpenTitan Cryptographic Library. These tests run on silicon, FPGA, and Verilator environments using the OpenTitan Test Framework (OTTF).

## 1. Test Framework (OTTF) Structure
- **Entry Point:** Every test file must define `OTTF_DEFINE_TEST_CONFIG();` followed by `bool test_main(void)`.
- **Return Type:** `test_main` returns `true` on success and `false` on failure.
- **Hardware Initialization:** Almost all crypto tests require the entropy complex to be running. Always call `CHECK_STATUS_OK(entropy_testutils_auto_mode_init());` at the start of `test_main`.

## 2. Assertions & Error Handling
- **Status Checks:** Use `CHECK_STATUS_OK(expr)` to verify that a function returning `status_t` succeeds.
- **Internal Flow:** Use `TRY()` to propagate errors within helper functions that return `status_t`.
- **Logic Checks:** Use `CHECK(condition)` for booleans, and `CHECK_ARRAYS_EQ()` / `CHECK_ARRAYS_NE()` for buffer comparisons.

## 3. Negative Testing Paradigm
A major requirement for OpenTitan crypto tests is robust negative testing. When writing tests, proactively generate cases for `OTCRYPTO_BAD_ARGS`:
- **NULL Pointers:** Pass `NULL` for buffers and key structs.
- **Invalid Key Modes:** Copy a valid configuration but mutate the `key_mode`.
- **Invalid Lengths:** Pass lengths that do not match the expected algorithm block size.
- **Corrupted Checksums:** Deliberately corrupt a key's integrity by XORing the checksum (e.g., `bad_key.checksum = valid_key.checksum ^ 0xFFFFFFFF;`).

## 4. OTBN Debugging
For tests involving asymmetric crypto (RSA, ECC), include debugging logic on failure to dump the OTBN state:
```c
if (!status_ok(err)) {
  LOG_INFO("OTBN error bits: 0x%08x", otbn_err_bits_get());
  LOG_INFO("OTBN instruction count: 0x%08x", otbn_instruction_count_get());
}
