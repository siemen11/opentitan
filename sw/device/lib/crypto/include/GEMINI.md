# OpenTitan Crypto Public API Context (include)

You are assisting in the design and documentation of the public-facing headers for the OpenTitan Cryptographic Library.

## 1. Naming Conventions
- **Functions:** Must be prefixed with `otcrypto_`. 
- **Types:** Use the `otcrypto_` prefix for library-specific structs and enums.
- **Macros:** Include guards must follow the full path: `OPENTITAN_SW_DEVICE_LIB_CRYPTO_INCLUDE_[FILENAME]_H_`.

## 2. API Design Patterns
- **Return Codes:** Every public function must return `otcrypto_status_t`.
- **Unused Results:** Annotate every function with the `OT_WARN_UNUSED_RESULT` macro.
- **Async Operations:** For high-latency hardware operations (like RSA/ECC), provide a split API:
  - `otcrypto_..._async_start(...)`
  - `otcrypto_..._async_finalize(...)`
- **Verification Logic:** For signature or MAC verification, the status code indicates if the *operation* succeeded. The actual *match* result must be returned via a `hardened_bool_t *verification_result` parameter.

## 3. Data Structures (datatypes.h)
- **Blinded Keys:** Private or secret data must use `otcrypto_blinded_key_t`. 
- **Unblinded Keys:** Public data (like ECC public points) must use `otcrypto_unblinded_key_t`.
- **Buffer Handling:** Use `otcrypto_const_byte_buf_t` or `otcrypto_word32_buf_t` rather than raw pointers for spans of data.

## 4. Documentation & Doxygen
- Use `@brief` for a one-line summary.
- Every parameter must be documented with `@param[in]`, `@param[out]`, or `@param[in,out]`.
- Note the **allocation responsibility**: Generally, the caller is responsible for allocating all buffers and key structs.

## 5. Build & Environment
- These headers are sensitive to the `OTCRYPTO_IN_REPO` define. 
- Ensure `cc_library` targets in `BUILD` include `//sw/device/lib/base:hardened` and `//sw/device/lib/base:status` as dependencies.
