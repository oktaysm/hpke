
#include <assert.h>
#include <hpke/hpke.h>
#include <hpke/hpke_locl.h>
#include <hpke/kem.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include "openssl/ossl_typ.h"

int32_t kem_x25519_keygen(uint16_t kem, uint8_t* sk, uint8_t* pk) {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx == NULL)
        goto err;
    if (EVP_PKEY_keygen_init(ctx) != 1)
        goto err;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1)
        goto err;
    uint64_t size;
    size = kems[HPKE_KEM_DHKEM_X25519].Npk;
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &size) != 1)
        goto err;
    size = kems[HPKE_KEM_DHKEM_X25519].Nsk;
    if (EVP_PKEY_get_raw_private_key(pkey, sk, &size) != 1)
        goto err;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
}

int32_t kem_x25519_derive(uint16_t kem, const uint8_t* sk, uint8_t* pk) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, NULL, sk, kems[HPKE_KEM_DHKEM_X25519].Nsk);
    if (pkey == NULL)
        goto err;
    uint64_t pkSize = kems[HPKE_KEM_DHKEM_X25519].Npk;
    if (EVP_PKEY_get_raw_public_key(pkey, pk, &pkSize) != 1)
        goto err;
    EVP_PKEY_free(pkey);
    return 0;
err:
    EVP_PKEY_free(pkey);
    return -1;
}

int32_t kem_x25519_dh(uint16_t kem, const uint8_t* sk, const uint8_t* pk,
                      uint8_t* dh) {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkPkey = NULL;
    EVP_PKEY* skPkey = NULL;

    pkPkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk,
                                         kems[HPKE_KEM_DHKEM_X25519].Npk);
    if (pkPkey == NULL)
        goto err;
    skPkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk,
                                          kems[HPKE_KEM_DHKEM_X25519].Nsk);
    if (skPkey == NULL)
        goto err;
    ctx = EVP_PKEY_CTX_new(skPkey, NULL);
    if (ctx == NULL)
        goto err;

    if (EVP_PKEY_derive_init(ctx) != 1)
        goto err;
    if (EVP_PKEY_derive_set_peer(ctx, pkPkey) != 1)
        goto err;

    uint64_t size = kems[HPKE_KEM_DHKEM_X25519].Nsk;
    if (EVP_PKEY_derive(ctx, dh, &size) != 1)
        goto err;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkPkey);
    EVP_PKEY_free(skPkey);
    return 0;
err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkPkey);
    EVP_PKEY_free(skPkey);
    return -1;
}

int32_t kem_nist_keygen(uint16_t kem, uint8_t* sk, uint8_t* pk) {
    const char* name;
    if (kem == HPKE_KEM_DHKEM_P512) {
        name = "P-521";
    } else if (kem == HPKE_KEM_DHKEM_P384) {
        name = "P-384";
    } else if (kem == HPKE_KEM_DHKEM_P256) {
        name = "P-256";
    } else {
        return -1;
    }

    EC_KEY* keyA = EC_KEY_new_by_curve_name(EC_curve_nist2nid(name));
    if (keyA == NULL)
        goto err;
    if (EC_KEY_generate_key(keyA) != 1)
        goto err;
    const EC_GROUP* group = EC_KEY_get0_group(keyA);
    const EC_POINT* pointA = EC_KEY_get0_public_key(keyA);
    const BIGNUM* skA = EC_KEY_get0_private_key(keyA);

    if (EC_POINT_point2oct(group, pointA, POINT_CONVERSION_UNCOMPRESSED, pk,
                           kems[kem].Npk, NULL) == 0)
        goto err;
    if (BN_bn2binpad(skA, sk, kems[kem].Nsk) <= 0)
        goto err;
    EC_KEY_free(keyA);
    return 0;
err:
    EC_KEY_free(keyA);
    return -1;
}

int32_t kem_nist_derive(uint16_t kem, const uint8_t* sk, uint8_t* pk) {
    const char* name;
    if (kem == HPKE_KEM_DHKEM_P512) {
        name = "P-521";
    } else if (kem == HPKE_KEM_DHKEM_P384) {
        name = "P-384";
    } else if (kem == HPKE_KEM_DHKEM_P256) {
        name = "P-256";
    } else {
        return -1;
    }
    BIGNUM* bnLocal = NULL;
    EC_POINT* point = NULL;
    EC_GROUP* group = NULL;
    group = EC_GROUP_new_by_curve_name(EC_curve_nist2nid(name));
    if (group == NULL)
        goto err;
    bnLocal = BN_bin2bn(sk, kems[kem].Nsk, NULL);
    if (bnLocal == NULL)
        goto err;
    point = EC_POINT_new(group);
    if (point == NULL)
        goto err;
    if (EC_POINT_mul(group, point, bnLocal, NULL, NULL, NULL) != 1)
        goto err;
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, pk,
                           kems[kem].Npk, NULL) == 0)
        goto err;
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_free(bnLocal);
    return 0;
err:
    EC_GROUP_free(group);
    EC_POINT_free(point);
    BN_free(bnLocal);
    return -1;
}

int32_t kem_nist_dh(uint16_t kem, const uint8_t* sk, const uint8_t* pk,
                    uint8_t* dh) {
    const char* name;
    if (kem == HPKE_KEM_DHKEM_P512) {
        name = "P-521";
    } else if (kem == HPKE_KEM_DHKEM_P384) {
        name = "P-384";
    } else if (kem == HPKE_KEM_DHKEM_P256) {
        name = "P-256";
    } else {
        return -1;
    }
    EC_KEY* keyLocal = NULL;
    BIGNUM* bnLocal = NULL;
    EC_POINT* pointPeer = NULL;

    keyLocal = EC_KEY_new_by_curve_name(EC_curve_nist2nid(name));
    if (keyLocal == NULL)
        goto err;
    const EC_GROUP* group = EC_KEY_get0_group(keyLocal);
    bnLocal = BN_bin2bn(sk, kems[kem].Nsk, NULL);
    if (bnLocal == NULL)
        goto err;
    if (EC_KEY_set_private_key(keyLocal, bnLocal) != 1)
        goto err;

    pointPeer = EC_POINT_new(group);
    if (pointPeer == NULL)
        goto err;
    if (EC_POINT_oct2point(group, pointPeer, pk, kems[kem].Npk, NULL) != 1)
        goto err;
    if (ECDH_compute_key(dh, kems[kem].Nsk, pointPeer, keyLocal, NULL) == -1)
        goto err;

    BN_free(bnLocal);
    EC_KEY_free(keyLocal);
    EC_POINT_free(pointPeer);
    return 0;
err:
    BN_free(bnLocal);
    EC_KEY_free(keyLocal);
    EC_POINT_free(pointPeer);
    return -1;
}