#pragma once

#include <stdint.h>

typedef struct {
    const uint8_t* b;
    uint32_t s;
} hpke_array_ref_t;

typedef struct {
    uint16_t mode;
    uint16_t kem_id;
    uint16_t kdf_id;
    uint16_t aead_id;
} hpke_t;

typedef struct {
    hpke_t suite;
    uint8_t key[32];
    uint8_t base_nonce[12];
    uint64_t seq;
    uint8_t exporter_secret[64];
} hpke_ctx_t;

#define HPKE_MODE_BASE 0
#define HPKE_MODE_PSK 1
#define HPKE_MODE_AUTH 2
#define HPKE_MODE_AUTH_PSK 3

#define HPKE_KEM_DHKEM_P256 0
#define HPKE_KEM_DHKEM_P384 1
#define HPKE_KEM_DHKEM_P512 2
#define HPKE_KEM_DHKEM_X25519 3
// #define HPKE_KEM_DHKEM_X448 4
// not implemented by LibreSSL yet

#define HPKE_KDF_SHA256 0
#define HPKE_KDF_SHA384 1
#define HPKE_KDF_SHA512 2

#define HPKE_AEAD_AES128_GCM 0
#define HPKE_AEAD_AES256_GCM 1
#define HPKE_AEAD_CHACHA20_POLY1305 2

#define DLL_PUBLIC __attribute__((visibility("default")))

DLL_PUBLIC int32_t HPKE_Encap(uint32_t kem_id, const uint8_t* pkR,
                              uint8_t* shared_secret, uint8_t* enc);
DLL_PUBLIC int32_t HPKE_Decap(uint32_t kem_id, const uint8_t* skR,
                              const uint8_t* enc, uint8_t* shared_secret);
DLL_PUBLIC int32_t HPKE_AuthEncap(uint32_t kem_id, const uint8_t* pkR,
                                  const uint8_t* skS, uint8_t* shared_secret,
                                  uint8_t* enc);
DLL_PUBLIC int32_t HPKE_AuthDecap(uint32_t kem_id, const uint8_t* skR,
                                  const uint8_t* pkS, const uint8_t* enc,
                                  uint8_t* shared_secret);

DLL_PUBLIC int32_t HPKE_SetupS(hpke_t suite, const uint8_t* pkR,
                               hpke_array_ref_t info, hpke_array_ref_t psk,
                               hpke_array_ref_t psk_id, uint8_t* enc,
                               hpke_ctx_t* ctx);
DLL_PUBLIC int32_t HPKE_SetupR(hpke_t suite, const uint8_t* enc,
                               const uint8_t* skR, hpke_array_ref_t info,
                               hpke_array_ref_t psk, hpke_array_ref_t psk_id,
                               hpke_ctx_t* ctx);
DLL_PUBLIC int32_t HPKE_SetupAuthS(hpke_t suite, const uint8_t* pkR,
                                   const uint8_t* skS, hpke_array_ref_t info,
                                   hpke_array_ref_t psk,
                                   hpke_array_ref_t psk_id, uint8_t* enc,
                                   hpke_ctx_t* ctx);
DLL_PUBLIC int32_t HPKE_SetupAuthR(hpke_t suite, const uint8_t* enc,
                                   const uint8_t* skR, const uint8_t* pkS,
                                   hpke_array_ref_t info, hpke_array_ref_t psk,
                                   hpke_array_ref_t psk_id, hpke_ctx_t* ctx);

DLL_PUBLIC int32_t HPKE_Seal(hpke_ctx_t* ctx, hpke_array_ref_t aad,
                             hpke_array_ref_t plain, uint8_t* ct);
DLL_PUBLIC int32_t HPKE_Open(hpke_ctx_t* ctx, hpke_array_ref_t aad,
                             hpke_array_ref_t ct, uint8_t* plain);