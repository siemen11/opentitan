# AES-GCM & GHASH Implementation Context

## Galois Field Math
- This implementation uses a 4-bit windowed approach for GHASH.
- **Constant Time:** All bit-shifting (`block_shiftr`) and multiplications (`galois_mulx`) must be constant-time.
- **Endianness:** NIST SP800-38D uses big-endian block representation. Since the Ibex processor is little-endian, use `__builtin_bswap32` where necessary.

## Integrity
- Contexts (like `ghash_context_t`) must have a checksum.
- Always verify the context checksum with `ghash_context_integrity_checksum_check` at the start of update/final operations.
