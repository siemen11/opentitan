# OpenTitan Crypto Library Guide

You are assisting a developer/security analyst working on the `sw/device/lib/crypto` library.

### Core Constraints
* **Return Types:** Use `otcrypto_status_t` for all API functions.
* **Hardened Booleans:** Use `kHardenedBoolTrue` and `kHardenedBoolFalse` from `hardened.h`.
* **Error Handling:** Use the `HARDENED_TRY()` macro for checking status codes.
* **No Dynamic Allocation:** Memory must be provided by the caller or be static.

### Hardware Awareness
* Refer to the **OTBN** (OpenTitan Big Number) documentation when dealing with RSA or ECC implementations.
* Use existing hardware wrappers for **AES**, **KMAC**, and **HMAC**.

### Code Style
* Follow the [OpenTitan C Style Guide].
* Ensure all sensitive comparisons use constant-time functions.
