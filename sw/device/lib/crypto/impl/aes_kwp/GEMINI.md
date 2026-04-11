# AES-KWP Implementation Context

This directory implements the AES Key Wrap with Padding (KWP) algorithm, primarily used for secure key transport.

## Algorithm Specifics
- **Standards:** Follows NIST SP800-38F.
- **Underlying Driver:** Relies on the AES hardware driver in `//sw/device/lib/crypto/drivers:aes`.
- **Block Handling:** KWP involves an 8-byte integrity check (the "semiblock"). Ensure the wrap/unwrap logic correctly handles the prepending/validation of this value.

## Implementation Rules
- **Constant Time:** The wrapping and unwrapping loops must be constant-time to prevent timing attacks on the wrapped key.
- **Integrity Failures:** If an unwrapping integrity check fails, return `OTCRYPTO_RECOV_ERR` and **immediately** shred the temporary buffers using `hardened_memshred`.
- **Alignment:** Input keys for wrapping are often not block-aligned; handle the partial block padding strictly according to the spec.
