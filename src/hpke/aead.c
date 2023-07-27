
#include <assert.h>
#include <hpke/aead.h>
#include <openssl/evp.h>
#include <hpke/hpke.h>
#include <hpke/hpke_locl.h>

int32_t aead_seal(uint16_t aead_id, const uint8_t *key, const uint8_t *nonce,
                  uint32_t aad_bytes, const uint8_t *aad, uint32_t in_bytes,
                  const uint8_t *in, uint32_t out_bytes, uint8_t *out) {
    const EVP_AEAD *evp_aead;
    if (aead_id == HPKE_AEAD_CHACHA20_POLY1305) {
        evp_aead = EVP_aead_chacha20_poly1305();
    } else if (aead_id == HPKE_AEAD_AES256_GCM) {
        evp_aead = EVP_aead_aes_256_gcm();
    } else if (aead_id == HPKE_AEAD_AES128_GCM) {
        evp_aead = EVP_aead_aes_128_gcm();
    } else {
        return -1;
    }
    assert(in_bytes + aeads[aead_id].Nt == out_bytes);

    uint64_t res;
    EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new();
    EVP_AEAD_CTX_init(ctx, evp_aead, key, aeads[aead_id].Nk, aeads[aead_id].Nt,
                      NULL);
    if (ctx == NULL)
        goto err;
    uint32_t ret =
        EVP_AEAD_CTX_seal(ctx, out, &res, out_bytes, nonce, aeads[aead_id].Nn,
                          in, in_bytes, aad, aad_bytes);
    EVP_AEAD_CTX_free(ctx);
    if (ret) {
        return 0;
    }
    return 1;
err:
    EVP_AEAD_CTX_free(ctx);
    return -1;
}

int32_t aead_open(uint16_t aead_id, const uint8_t *key, const uint8_t *nonce,
                  uint32_t aad_bytes, const uint8_t *aad, uint32_t in_bytes,
                  const uint8_t *in, uint32_t out_bytes, uint8_t *out) {
    const EVP_AEAD *evp_aead;
    if (aead_id == HPKE_AEAD_CHACHA20_POLY1305) {
        evp_aead = EVP_aead_chacha20_poly1305();
    } else if (aead_id == HPKE_AEAD_AES256_GCM) {
        evp_aead = EVP_aead_aes_256_gcm();
    } else if (aead_id == HPKE_AEAD_AES128_GCM) {
        evp_aead = EVP_aead_aes_128_gcm();
    } else {
        return -1;
    }
    assert(out_bytes + aeads[aead_id].Nt == in_bytes);

    uint64_t res;
    EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new();
    EVP_AEAD_CTX_init(ctx, evp_aead, key, aeads[aead_id].Nk, aeads[aead_id].Nt,
                      NULL);
    if (ctx == NULL)
        goto err;
    uint32_t ret =
        EVP_AEAD_CTX_open(ctx, out, &res, out_bytes, nonce, aeads[aead_id].Nn,
                          in, in_bytes, aad, aad_bytes);
    EVP_AEAD_CTX_free(ctx);
    if (ret) {
        return 0;
    }
    return 1;
err:
    EVP_AEAD_CTX_free(ctx);
    return -1;
}
