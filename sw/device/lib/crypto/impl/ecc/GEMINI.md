# ECC Implementation Context (OTBN)

## OTBN Relationship
- This directory contains the C wrapper logic for ECC. 
- **CRITICAL:** The actual assembly/arithmetic implementation (the .s and .pmp files) is located in `//sw/otbn/crypto`.
- When modifying ECC logic, refer to the OTBN app names (e.g., `p256_ecdsa_save`) defined in the OTBN headers.

## Data Alignment
- Ensure all buffers passed to OTBN are aligned to 32-bit words (OTBN requirements).
- Use `otbn_write_data` and `otbn_read_data` to interface with the processor.
