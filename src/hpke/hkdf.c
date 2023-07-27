
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <openssl/hmac.h>
#include <hpke/utils.h>
#include <hpke/hkdf.h>
#include <hpke/hpke.h>
#include <hpke/hpke_locl.h>

int32_t hkdf_extract(uint16_t kdf_id, const uint8_t* salt, uint32_t salt_bytes,
                     const uint8_t* ikm, uint32_t ikm_bytes, uint8_t* md) {
    const EVP_MD* evp_md;
    if (kdf_id == HPKE_KDF_SHA256) {
        evp_md = EVP_sha256();
    } else if (kdf_id == HPKE_KDF_SHA384) {
        evp_md = EVP_sha384();
    } else if (kdf_id == HPKE_KDF_SHA512) {
        evp_md = EVP_sha512();
    }
    if (HMAC(evp_md, salt, salt_bytes, ikm, ikm_bytes, md, NULL) == NULL)
        return -1;
    return 0;
}

int32_t hkdf_expand(uint16_t kdf_id, const uint8_t* prk, uint32_t prk_bytes,
                    const uint8_t* info, uint32_t info_bytes, uint8_t* okm,
                    uint32_t okm_bytes) {
    const EVP_MD* evp_md;
    const uint32_t keyLen = kdf[kdf_id].Nh;
    if (kdf_id == HPKE_KDF_SHA256) {
        evp_md = EVP_sha256();
    } else if (kdf_id == HPKE_KDF_SHA384) {
        evp_md = EVP_sha384();
    } else if (kdf_id == HPKE_KDF_SHA512) {
        evp_md = EVP_sha512();
    } else {
        return -1;
    }

    assert(okm_bytes < 0x100 * keyLen);

    uint32_t rlen;
    uint32_t n = CEIL(okm_bytes, keyLen);
    uint8_t counter = 0x01;
    uint8_t hash[keyLen * n];

    HMAC_CTX* hmac = HMAC_CTX_new();
    if (hmac == NULL)
        goto err;

    if (HMAC_Init_ex(hmac, prk, prk_bytes, evp_md, NULL) != 1)
        goto err;
    if (HMAC_Update(hmac, info, info_bytes) != 1)
        goto err;
    if (HMAC_Update(hmac, &counter, 1) != 1)
        goto err;
    if (HMAC_Final(hmac, hash, &rlen) != 1)
        goto err;

    for (int i = 1; i < n; i++) {
        counter = i + 1;
        if (HMAC_Init_ex(hmac, prk, prk_bytes, evp_md, NULL) != 1)
            goto err;
        if (HMAC_Update(hmac, hash + keyLen * (i - 1), keyLen) != 1)
            goto err;
        if (HMAC_Update(hmac, info, info_bytes) != 1)
            goto err;
        if (HMAC_Update(hmac, &counter, 1) != 1)
            goto err;
        if (HMAC_Final(hmac, hash + keyLen * i, &rlen) != 1)
            goto err;
    }
    memcpy(okm, hash, okm_bytes);
    HMAC_CTX_free(hmac);
    explicit_bzero(hash, sizeof(hash));
    return 0;
err:
    HMAC_CTX_free(hmac);
    explicit_bzero(hash, sizeof(hash));
    return -1;
}
