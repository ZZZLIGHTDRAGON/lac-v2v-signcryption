#include "api.h"

#ifdef _WIN32
#define LAC_BRIDGE_API __declspec(dllexport)
#else
#define LAC_BRIDGE_API
#endif

LAC_BRIDGE_API int lac_public_key_bytes(void)
{
    return CRYPTO_PUBLICKEYBYTES;
}

LAC_BRIDGE_API int lac_secret_key_bytes(void)
{
    return CRYPTO_SECRETKEYBYTES;
}

LAC_BRIDGE_API int lac_message_bytes(void)
{
    return CRYPTO_BYTES;
}

LAC_BRIDGE_API int lac_ciphertext_bytes(void)
{
    return CRYPTO_CIPHERTEXTBYTES;
}

LAC_BRIDGE_API int lac_pke_keypair(unsigned char *pk, unsigned char *sk)
{
    return crypto_encrypt_keypair(pk, sk);
}

LAC_BRIDGE_API int lac_pke_encrypt(
    unsigned char *c,
    unsigned long long *clen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *pk
)
{
    return crypto_encrypt(c, clen, m, mlen, pk);
}

LAC_BRIDGE_API int lac_pke_decrypt(
    unsigned char *m,
    unsigned long long *mlen,
    const unsigned char *c,
    unsigned long long clen,
    const unsigned char *sk
)
{
    return crypto_encrypt_open(m, mlen, c, clen, sk);
}

LAC_BRIDGE_API int lac_wrap_partial_key(
    unsigned char *c,
    unsigned long long *clen,
    const unsigned char *partial_key,
    unsigned long long partial_key_len,
    const unsigned char *temp_pk
)
{
    return crypto_encrypt(c, clen, partial_key, partial_key_len, temp_pk);
}

LAC_BRIDGE_API int lac_unwrap_partial_key(
    unsigned char *partial_key,
    unsigned long long *partial_key_len,
    const unsigned char *c,
    unsigned long long clen,
    const unsigned char *temp_sk
)
{
    return crypto_encrypt_open(partial_key, partial_key_len, c, clen, temp_sk);
}

LAC_BRIDGE_API int lac_kem_keypair(unsigned char *pk, unsigned char *sk)
{
    return crypto_kem_keypair(pk, sk);
}

LAC_BRIDGE_API int lac_kem_encapsulate(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk
)
{
    return crypto_kem_enc(ct, ss, pk);
}

LAC_BRIDGE_API int lac_kem_decapsulate(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk
)
{
    return crypto_kem_dec(ss, ct, sk);
}
