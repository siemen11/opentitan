# SHA2 Implementation Context (OTBN-backed)

While OpenTitan has an HMAC/SHA2 hardware IP, these specific implementations (`sha256.c`, `sha512.c`) target **OTBN** for specific big-number or high-security flows.

## Core logic
- **OTBN Offload:** Actual hash computation is performed by OTBN apps in `//sw/otbn/crypto:run_sha256` and `//sw/otbn/crypto:run_sha512`.
- **Digest Handling:** Digests are returned from OTBN. Ensure they are moved into the destination buffer using `hardened_memcpy` or `randomized_bytecopy`.

## Implementation Constraints
- **SHA-512 on 32-bit:** Since Ibex is a 32-bit processor, be extra careful with 64-bit word handling in the C wrappers for SHA-512. Use `sw/device/lib/base/math.h` if 64-bit emulation helpers are needed.
- **Dependencies:** Always depend on `//sw/device/lib/crypto/drivers:otbn` and the corresponding OTBN library.

## Performance vs. Security
- These implementations prioritize side-channel resistance over the raw throughput of the dedicated HMAC/SHA IP. Use these when the hash is part of a larger sensitive protocol (like signing).
