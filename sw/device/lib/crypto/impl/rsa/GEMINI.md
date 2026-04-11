# RSA Implementation Context (OTBN-backed)

This directory manages RSA encryption, decryption, and signatures. The core modular exponentiation is offloaded to **OTBN**.

## OTBN Integration
- **Heavy Lifting:** Arithmetic logic is located in `//sw/otbn/crypto`. Specifically use `run_rsa` and `run_rsa_key_from_cofactor`.
- **Memory Alignment:** All data passed to/from OTBN must be 32-bit word aligned. 
- **Instruction Flow:** Always ensure the OTBN app is loaded and the hardware is idle before triggering RSA operations.

## Padding & Security
- **Padding Modes:** Supports both PSS (signatures) and OAEP (encryption). 
- **Randomness:** Padding requires high-quality entropy; ensure the entropy complex is checked before generating masks.
- **Key Formats:** RSA keys are often handled via cofactors. Ensure `rsa_datatypes.h` is the source of truth for key structures.

## Coding Patterns
- Use `HARDENED_TRY()` for all OTBN driver calls.
- Use `random_order` macros where applicable during padding to mitigate side-channel leakage.
