// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_uart.h"
#include "sw/device/lib/runtime/hart.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

#include "sw/device/tests/dilithium_lib/packing.h"
#include "sw/device/tests/dilithium_lib/poly.h"
#include "sw/device/tests/dilithium_lib/polyvec.h"
#include "sw/device/tests/dilithium_lib/fips202.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

OTTF_DEFINE_TEST_CONFIG(.enable_concurrency = false,
                        .console.test_may_clobber = true, );

#define MLEN 59
#define NTESTS 1

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  uint8_t tr[SEEDBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  memset(seedbuf, 0x0, 2*SEEDBYTES + CRHBYTES);
  for(int r = 0; r < SEEDBYTES; r++) {
    seedbuf[r] = (uint8_t)r;
  }

  uint64_t start = ibex_mcycle_read();
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;
  uint64_t end = ibex_mcycle_read();
  LOG_INFO("Expand seed = %u cycles", (uint32_t)(end - start));

  /* Expand matrix */
  start = ibex_mcycle_read();
  polyvec_matrix_expand(mat, rho);
  end = ibex_mcycle_read();

  /* Sample short vectors s1 and s2 */
  start = ibex_mcycle_read();
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);
  end = ibex_mcycle_read();
  LOG_INFO("sample short vectors s1 and s2 = %u cycles", (uint32_t)(end - start));

  /* Matrix-vector multiplication */
  start = ibex_mcycle_read();
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);
  end = ibex_mcycle_read();
  LOG_INFO("Matrix vector mult = %u cycles", (uint32_t)(end - start));

  /* Add error vector s2 */
  start = ibex_mcycle_read();
  polyveck_add(&t1, &t1, &s2);
  end = ibex_mcycle_read();
  LOG_INFO("Add error vector = %u cycles", (uint32_t)(end - start));

  /* Extract t1 and write public key */
  start = ibex_mcycle_read();
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);
  end = ibex_mcycle_read();
  LOG_INFO("Extract t1 = %u cycles", (uint32_t)(end - start));

  /* Compute H(rho, t1) and write secret key */
  start = ibex_mcycle_read();
  shake256(tr, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
  end = ibex_mcycle_read();
  LOG_INFO("Compute H = %u cycles", (uint32_t)(end - start));

  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[3*SEEDBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + SEEDBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  uint64_t start = ibex_mcycle_read();
  shake256_init(&state);
  shake256_absorb(&state, tr, SEEDBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);
  uint64_t end = ibex_mcycle_read();
  LOG_INFO("Compute CRH(tr, msg) = %u cycles", (uint32_t)(end - start));

  start = ibex_mcycle_read();
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);
  end = ibex_mcycle_read();
  LOG_INFO("Compute private random seed = %u cycles", (uint32_t)(end - start));

  /* Expand matrix and transform vectors */
  start = ibex_mcycle_read();
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);
  end = ibex_mcycle_read();
  LOG_INFO("Expand matrix and transform vectors = %u cycles", (uint32_t)(end - start));

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  start = ibex_mcycle_read();
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);
  end = ibex_mcycle_read();
  LOG_INFO("Matrix-vector multiplication = %u cycles", (uint32_t)(end - start));

  /* Decompose w and call the random oracle */
  start = ibex_mcycle_read();
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);
  end = ibex_mcycle_read();
  LOG_INFO("Decompose w and call the random oracle = %u cycles", (uint32_t)(end - start));

  start = ibex_mcycle_read();
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, SEEDBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);
  end = ibex_mcycle_read();
  LOG_INFO("Compute commitment hash = %u cycles", (uint32_t)(end - start));

  /* Compute z, reject if it reveals secret */
  start = ibex_mcycle_read();
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;
  end = ibex_mcycle_read();
  LOG_INFO("Compute z, reject if it reveals secret = %u cycles", (uint32_t)(end - start));

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  start = ibex_mcycle_read();
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;
  end = ibex_mcycle_read();
  LOG_INFO("Checks cs2 = %u cycles", (uint32_t)(end - start));

  /* Compute hints for w1 */
  start = ibex_mcycle_read();
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  end = ibex_mcycle_read();
  LOG_INFO("Compute hints for w1 = %u cycles", (uint32_t)(end - start));

  /* Write signature */
  start = ibex_mcycle_read();
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;
  end = ibex_mcycle_read();
  LOG_INFO("Write signature = %u cycles", (uint32_t)(end - start));
  return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
  *smlen += mlen;
  return 0;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  keccak_state state;

  if(siglen != CRYPTO_BYTES) {
    LOG_INFO("siglen -1");
    return -1;
  }

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig)) {
    LOG_INFO("unpack_sig -1");
    return -1;
  }
  if(polyvecl_chknorm(&z, GAMMA1 - BETA)) {
    LOG_INFO("polyvecl_chknorm -1");
    return -1;
  }

  /* Compute CRH(H(rho, t1), msg) */
  uint64_t start = ibex_mcycle_read();
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, SEEDBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);
  uint64_t end = ibex_mcycle_read();
  LOG_INFO("Compute Compute CRH(H(rho, t1), msg) = %u cycles", (uint32_t)(end - start));

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  start = ibex_mcycle_read();
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);
  end = ibex_mcycle_read();
  LOG_INFO("Matrix-vector multiplication; compute Az - c2^dt1 = %u cycles", (uint32_t)(end - start));

  /* Reconstruct w1 */
  start = ibex_mcycle_read();
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);
  end = ibex_mcycle_read();
  LOG_INFO("Reconstruct w1 = %u cycles", (uint32_t)(end - start));

  /* Call random oracle and verify challenge */
  start = ibex_mcycle_read();
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, SEEDBYTES, &state);
  for(i = 0; i < SEEDBYTES; ++i) {
    if(c[i] != c2[i]) {
      return -1;
    }
  }
  end = ibex_mcycle_read();
  LOG_INFO("Call random oracle and verify challenge = %u cycles", (uint32_t)(end - start));
      

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = (size_t)-1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;
  LOG_INFO("verification failed badsig");
  return -1;
}

bool test_main(void) {
  LOG_INFO("Starting DILITHIUM test...");

  size_t j;
  int ret;
  size_t mlen, smlen;
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t m[MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  memset(m, 0x0, MLEN + CRYPTO_BYTES);

  for(int r = 0; r < MLEN; r++) {
    m[r] = (uint8_t)r;
  }

  uint64_t start = ibex_mcycle_read();
  crypto_sign_keypair(pk, sk);
  uint64_t end = ibex_mcycle_read();
  if (end - start > UINT32_MAX) {
    LOG_FATAL("crypto_sign_keypair() took more than UINT32_MAX cycles");
    return false;
  }
  LOG_INFO("creating keypair took %u cycles", (uint32_t)(end - start));

  start = ibex_mcycle_read();
  crypto_sign(sm, &smlen, m, MLEN, sk);
  end = ibex_mcycle_read();
  if (end - start > UINT32_MAX) {
    LOG_FATAL("crypto_sign() took more than UINT32_MAX cycles");
    return false;
  }
  LOG_INFO("signing message took %u cycles", (uint32_t)(end - start));

  start = ibex_mcycle_read();
  ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
  end = ibex_mcycle_read();
  if (end - start > UINT32_MAX) {
    LOG_FATAL("crypto_sign_open() took more than UINT32_MAX cycles");
    return false;
  }
  LOG_INFO("verifying message took %u cycles", (uint32_t)(end - start));

  if(ret) {
    LOG_INFO("Verification failed.");
    return false;
  }

  if(smlen != MLEN + CRYPTO_BYTES) {
      LOG_INFO("Signed message lengths wrong.");
      return false;
  }
  if(mlen != MLEN) {
    LOG_INFO("Message lengths wrong.");
    return false;
  }
  for(j = 0; j < MLEN; ++j) {
    if(m2[j] != m[j]) {
      LOG_INFO("Messages don't match.");
      return false;
    }
  }

  LOG_INFO("Finished DILITHIUM test.");
  return true;
}
