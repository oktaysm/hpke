#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <hpke/utils.h>
#include <hpke/hkdf.h>
#include <hpke/aead.h>
#include <hpke/kem.h>
#include <hpke/hpke_locl.h>

// https://www.rfc-editor.org/rfc/rfc5869.html testcase5
int test_hkdf_sha256(void* data) {
    static const uint8_t ikm[80] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,

    };
    static const uint8_t salt[80] = {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
        0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf

    };
    static const uint8_t info[80] = {
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
        0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
        0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb,
        0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };
    static const uint32_t L = 82;

    static const uint8_t prk[32] = {
        0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c,
        0x9c, 0xeb, 0x35, 0xb4, 0x5c, 0xef, 0x76, 0x00, 0x14, 0x90, 0x46,
        0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44,
    };
    static const uint8_t okm[82] = {
        0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c,
        0x59, 0x6a, 0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
        0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99,
        0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
        0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9,
        0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
        0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
    };
    uint8_t test_prk[32];
    uint8_t test_okm[L];

    hkdf_extract(HPKE_KDF_SHA256, salt, SIZEA(salt), ikm, SIZEA(ikm), test_prk);
    hkdf_expand(HPKE_KDF_SHA256, test_prk, SIZEA(test_prk), info, SIZEA(info),
                test_okm, L);

    int res = 1;
    res &= (memcmp(prk, test_prk, sizeof(prk)) == 0) ? 1 : 0;
    res &= (memcmp(okm, test_okm, L * sizeof(uint8_t)) == 0) ? 1 : 0;
    return res;
}

// https://www.rfc-editor.org/rfc/rfc8439.html
int test_aead_chacha20_poly1305(void* data) {
    static const uint8_t in[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47,
        0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66,
        0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
        0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
    };
    static const int bytes = 114;
    static uint8_t aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    };
    static const int aad_bytes = 12;
    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
        0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
        0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    static const uint8_t nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };

    static const uint8_t out[114] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
        0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
        0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
        0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
        0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    };
    static const uint8_t mac[16] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };
    // static uint8_t test_out[114];
    static uint8_t test_out[130];
    static uint8_t test_mac[16];

    uint32_t r1 = aead_seal(HPKE_AEAD_CHACHA20_POLY1305, key, nonce, aad_bytes,
                            aad, bytes, in, bytes + 16, test_out);
    memcpy(test_mac, test_out + bytes, 16 * sizeof(uint8_t));
    int res = 1;
    res &= !r1;
    res &= (memcmp(mac, test_mac, sizeof(mac)) == 0) ? 1 : 0;
    res &= (memcmp(out, test_out, bytes * sizeof(uint8_t)) == 0) ? 1 : 0;
    return res;
}

int test_aead_cp_endec(void* data) {
    static const uint8_t plain[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47,
        0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66,
        0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
        0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
    };
    static const int bytes = 114;
    static uint8_t aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    };
    static const int aad_bytes = 12;
    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
        0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
        0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    static const uint8_t nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    static const uint8_t mac[16] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };

    uint8_t test_mac_enc[16];
    uint8_t encrypted[130];
    uint8_t test_plain[114];

    uint32_t r1 = aead_seal(HPKE_AEAD_CHACHA20_POLY1305, key, nonce, aad_bytes,
                            aad, bytes, plain, bytes + 16, encrypted);
    memcpy(test_mac_enc, encrypted + bytes, 16 * sizeof(uint8_t));
    uint32_t r2 = aead_open(HPKE_AEAD_CHACHA20_POLY1305, key, nonce, aad_bytes,
                            aad, bytes + 16, encrypted, bytes, test_plain);

    int res = 1;
    res &= !r1;
    res &= !r2;
    res &= (memcmp(&mac, &test_mac_enc, sizeof(mac)) == 0) ? 1 : 0;
    res &= (memcmp(&plain, &test_plain, sizeof(plain)) == 0) ? 1 : 0;
    return res;
}

int test_hpke_encap(void* data) {
    uint8_t skR[32], pkR[65];

    kem_nist_keygen(HPKE_KEM_DHKEM_P256, skR, pkR);

    uint8_t ssSender[32];
    uint8_t ssRec[32];
    uint8_t enc[65];

    HPKE_Encap(HPKE_KEM_DHKEM_P256, pkR, ssSender, enc);
    HPKE_Decap(HPKE_KEM_DHKEM_P256, skR, enc, ssRec);

    int res = 1;
    res &=
        (memcmp(ssSender, ssRec, SIZEA(ssRec) * sizeof(uint8_t)) == 0) ? 1 : 0;
    return res;
}

int test_hpke_auth_encap(void* data) {
    uint32_t skSize, pkSize, ssSize;
    HPKE_Keysize(HPKE_KEM_DHKEM_P384, &skSize, &pkSize, &ssSize);

    uint8_t skR[skSize], pkR[pkSize];
    uint8_t skS[skSize], pkS[pkSize];
    HPKE_Keygen(HPKE_KEM_DHKEM_P384, skR, pkR);
    HPKE_Keygen(HPKE_KEM_DHKEM_P384, skS, pkS);

    uint8_t ssSender[ssSize];
    uint8_t ssRec[ssSize];
    uint8_t enc[pkSize];
    HPKE_AuthEncap(HPKE_KEM_DHKEM_P384, pkR, skS, ssSender, enc);
    HPKE_AuthDecap(HPKE_KEM_DHKEM_P384, skR, pkS, enc, ssRec);

    int res = 1;
    res &=
        (memcmp(ssSender, ssRec, SIZEA(ssRec) * sizeof(uint8_t)) == 0) ? 1 : 0;
    return res;
}

int test_hpke_setup_base(void* data) {
    uint8_t skR[66], pkR[133];
    kem_nist_keygen(HPKE_KEM_DHKEM_P512, skR, pkR);

    uint8_t enc[133];
    uint8_t info[] = "test app 01";

    hpke_t suite = {
        .mode = HPKE_MODE_BASE,
        .kem_id = HPKE_KEM_DHKEM_P512,
        .kdf_id = HPKE_KDF_SHA256,
        .aead_id = HPKE_AEAD_CHACHA20_POLY1305,
    };

    hpke_ctx_t ctxS = {};
    hpke_ctx_t ctxR = {};

    hpke_array_ref_t info_Ref = {info, SIZEA(info)};
    hpke_array_ref_t empty_Ref = {0, 0};

    HPKE_SetupS(suite, pkR, info_Ref, empty_Ref, empty_Ref, enc, &ctxS);
    HPKE_SetupR(suite, enc, skR, info_Ref, empty_Ref, empty_Ref, &ctxR);
    int res = 1;
    res &= (memcmp(&ctxS, &ctxR, sizeof(hpke_ctx_t)) == 0) ? 1 : 0;
    return res;
}

int test_hpke_setup_auth(void* data) {
    uint8_t skR[66], pkR[133];
    uint8_t skS[66], pkS[133];
    kem_nist_keygen(HPKE_KEM_DHKEM_P512, skR, pkR);
    kem_nist_keygen(HPKE_KEM_DHKEM_P512, skS, pkS);

    uint8_t enc[133];
    uint8_t info[] = "test app 01";

    hpke_t suite = {
        .mode = HPKE_MODE_AUTH,
        .kem_id = HPKE_KEM_DHKEM_P512,
        .kdf_id = HPKE_KDF_SHA384,
        .aead_id = HPKE_AEAD_AES256_GCM,
    };

    hpke_ctx_t ctxS = {};
    hpke_ctx_t ctxR = {};

    hpke_array_ref_t info_Ref = {info, SIZEA(info)};
    hpke_array_ref_t empty_Ref = {0, 0};

    HPKE_SetupAuthS(suite, pkR, skS, info_Ref, empty_Ref, empty_Ref, enc,
                    &ctxS);
    HPKE_SetupAuthR(suite, enc, skR, pkS, info_Ref, empty_Ref, empty_Ref,
                    &ctxR);
    int res = 1;
    res &= (memcmp(&ctxS, &ctxR, sizeof(hpke_ctx_t)) == 0) ? 1 : 0;
    return res;
}

int test_hpke_seal_open(void* data) {
    uint8_t skR[32], pkR[32];
    kem_x25519_derive(HPKE_KEM_DHKEM_X25519, skR, pkR);

    uint8_t enc[32];
    uint8_t info[] = "test app 01";

    hpke_t suite = {
        .mode = HPKE_MODE_BASE,
        .kem_id = HPKE_KEM_DHKEM_X25519,
        .kdf_id = HPKE_KDF_SHA512,
        .aead_id = HPKE_AEAD_CHACHA20_POLY1305,
    };

    hpke_ctx_t ctxS = {};
    hpke_ctx_t ctxR = {};

    hpke_array_ref_t info_Ref = {info, SIZEA(info)};
    hpke_array_ref_t empty_Ref = {0, 0};

    HPKE_SetupS(suite, pkR, info_Ref, empty_Ref, empty_Ref, enc, &ctxS);
    HPKE_SetupR(suite, enc, skR, info_Ref, empty_Ref, empty_Ref, &ctxR);

    uint8_t plain[] = "nuclear codes O.O";
    uint8_t test_plain[SIZEA(plain)];
    uint8_t ct[SIZEA(plain) + 16];  // 16 byte tag at end

    hpke_array_ref_t empty = {NULL, 0};
    hpke_array_ref_t plain_Ref = {plain, SIZEA(plain)};
    hpke_array_ref_t ct_Ref = {ct, SIZEA(ct)};

    int res = 1;

    HPKE_Seal(&ctxS, empty, plain_Ref, ct);
    res &= (HPKE_Open(&ctxR, empty, ct_Ref, test_plain)) ? 0 : 1;
    res &= (memcmp(&plain, &test_plain, sizeof(plain)) == 0) ? 1 : 0;
    return res;
}

int test_dh_nist512(void* data) {
    static const uint8_t localSk[] = {
        0x1,  0xd4, 0xe6, 0x83, 0xc9, 0x50, 0xbf, 0x8a, 0xd3, 0x83, 0x39,
        0xaa, 0x8f, 0xe6, 0x61, 0xbe, 0x0,  0x75, 0xfc, 0xb,  0xe9, 0x92,
        0x2c, 0x45, 0x41, 0x12, 0xce, 0x48, 0x76, 0xb0, 0x99, 0x8e, 0xed,
        0xa2, 0x5,  0xfe, 0x87, 0xc1, 0xc6, 0x7,  0xea, 0xa0, 0xeb, 0xe4,
        0x18, 0xee, 0x23, 0x10, 0x92, 0xda, 0xc2, 0xbf, 0x49, 0xdd, 0x5d,
        0xbd, 0xa5, 0x6,  0x6f, 0x31, 0xfa, 0xe7, 0x79, 0xd8, 0x2c, 0x5b,
    };
    static const uint8_t localPk[] = {
        0x4,  0x1,  0x61, 0x58, 0x18, 0xc8, 0xb5, 0xab, 0x5f, 0x1,  0x43, 0x1b,
        0xd6, 0x54, 0xb3, 0xb1, 0x29, 0x1d, 0x90, 0x7,  0x82, 0x42, 0x8f, 0x6c,
        0x46, 0xfc, 0x53, 0xce, 0x7a, 0xde, 0x7e, 0x61, 0x5d, 0x9a, 0xe,  0xe5,
        0x35, 0xc2, 0x99, 0x67, 0x10, 0x46, 0x27, 0xaa, 0x5d, 0x5a, 0xd9, 0xb6,
        0xa9, 0x14, 0xc4, 0xbf, 0x62, 0xa5, 0x3b, 0x5,  0xc4, 0x43, 0x57, 0x46,
        0x24, 0xea, 0x39, 0xc8, 0x1b, 0x9d, 0xa2, 0x1,  0x25, 0x95, 0x34, 0xeb,
        0x81, 0xc9, 0x7a, 0x67, 0x6b, 0x8f, 0xe9, 0xc7, 0x7e, 0x21, 0x44, 0xeb,
        0xec, 0x7b, 0x53, 0xb4, 0x5c, 0x6f, 0x3c, 0xe,  0x7,  0x89, 0xb9, 0x73,
        0xa5, 0x82, 0x36, 0xb,  0x20, 0xb3, 0xdd, 0x75, 0xaa, 0xa,  0x11, 0xd4,
        0xd,  0xa2, 0x28, 0x1,  0x48, 0xac, 0x48, 0xd3, 0xf,  0xaf, 0x80, 0x15,
        0x1,  0x7,  0x5b, 0x4,  0x4e, 0x0,  0x31, 0x8d, 0xcd, 0x48, 0xf4, 0x51,
        0xf5,
    };

    static const uint8_t peerSk[] = {
        0x0,  0x86, 0xe3, 0x90, 0x92, 0x11, 0x5a, 0x29, 0x9a, 0x5,  0xf8,
        0x86, 0x30, 0xd0, 0x47, 0xc2, 0xe7, 0x8a, 0x36, 0x52, 0xad, 0x31,
        0x70, 0x4,  0x2,  0x98, 0xd8, 0x6c, 0x87, 0x8c, 0xe4, 0xae, 0xf9,
        0xc0, 0x6e, 0x5f, 0x8a, 0xfa, 0x3,  0xec, 0x61, 0xaf, 0x7c, 0xca,
        0x45, 0xc7, 0x43, 0xc6, 0x26, 0x52, 0x78, 0xd5, 0x43, 0x74, 0xd2,
        0xe0, 0x64, 0x97, 0x37, 0x65, 0x90, 0x1c, 0x41, 0x33, 0x79, 0xef,
    };
    static const uint8_t peerPk[] = {
        0x4,  0x1,  0x7b, 0x88, 0x40, 0xce, 0xb7, 0x61, 0xc7, 0x44, 0x6,  0x28,
        0x17, 0x34, 0x62, 0x3b, 0x12, 0xf,  0xe4, 0x1b, 0x31, 0xfb, 0xd,  0xf3,
        0x8b, 0x49, 0xbc, 0xb3, 0xba, 0x2f, 0xae, 0x61, 0x4c, 0xdf, 0x92, 0x5d,
        0x33, 0x41, 0x39, 0xa7, 0x16, 0xd7, 0x89, 0xf7, 0xed, 0xf4, 0x82, 0x36,
        0x58, 0x5c, 0x7b, 0x5e, 0xca, 0x20, 0xac, 0xef, 0xd3, 0x76, 0x57, 0xbb,
        0x92, 0x31, 0x3e, 0x0,  0xe9, 0x65, 0x61, 0x1,  0xc8, 0x9f, 0x5f, 0x28,
        0xfd, 0xd4, 0x8b, 0xf3, 0x1b, 0x34, 0xa4, 0x4e, 0x87, 0x65, 0x89, 0xcb,
        0xf0, 0x17, 0x59, 0x40, 0x63, 0x19, 0x9c, 0xbe, 0xaa, 0x92, 0x4b, 0xd5,
        0xbc, 0x57, 0x66, 0x9c, 0x2f, 0xd1, 0xd2, 0xbb, 0x66, 0xd8, 0xdd, 0xf9,
        0x27, 0x3f, 0xa4, 0x91, 0xdf, 0xce, 0x6d, 0xd9, 0x3a, 0x69, 0x76, 0x25,
        0x3c, 0x12, 0x95, 0x78, 0x94, 0xd0, 0x43, 0xec, 0x4,  0x35, 0x79, 0xee,
        0x1c,
    };

    uint8_t enc[SIZEA(peerPk)];
    uint8_t info[] = "test app 01";
    const hpke_array_ref_t info_Ref = {info, SIZEA(info)};

    hpke_t suite = {
        .mode = HPKE_MODE_AUTH,
        .kem_id = HPKE_KEM_DHKEM_P512,
        .kdf_id = HPKE_KDF_SHA384,
        .aead_id = HPKE_AEAD_AES256_GCM,
    };

    hpke_ctx_t ctxS = {};
    hpke_ctx_t ctxR = {};
    hpke_array_ref_t empty_Ref = {0, 0};

    HPKE_SetupAuthS(suite, peerPk, localSk, info_Ref, empty_Ref, empty_Ref, enc,
                    &ctxS);
    HPKE_SetupAuthR(suite, enc, peerSk, localPk, info_Ref, empty_Ref, empty_Ref,
                    &ctxR);
    int res = 1;
    res &= (memcmp(&ctxS, &ctxR, sizeof(hpke_ctx_t)) == 0) ? 1 : 0;
    return res;
}

int test_rfc9180_a1(void* data) {
    const uint8_t info[] = {
        0x4f, 0x64, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x47,
        0x72, 0x65, 0x63, 0x69, 0x61, 0x6e, 0x20, 0x55, 0x72, 0x6e,
    };
    const uint8_t pkR[] = {
        0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69, 0x5d, 0x78, 0x0e,
        0x59, 0x07, 0x71, 0x95, 0xda, 0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73,
        0x29, 0x79, 0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81, 0x5c, 0x4d,
    };
    const uint8_t skR[] = {
        0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad, 0x58, 0x37, 0x5d,
        0xf3, 0xf5, 0x57, 0xaa, 0xc5, 0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e,
        0x55, 0xa9, 0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e, 0x8a, 0xc8,
    };
    const uint8_t pkE[] = {
        0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28, 0xe8, 0x86, 0x68,
        0xc3, 0xc8, 0xd7, 0xe9, 0x7d, 0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea,
        0x6d, 0x44, 0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31,
    };
    const uint8_t skE[] = {
        0x52, 0xc4, 0xa7, 0x58, 0xa8, 0x02, 0xcd, 0x8b, 0x93, 0x6e, 0xce,
        0xea, 0x31, 0x44, 0x32, 0x79, 0x8d, 0x5b, 0xaf, 0x2d, 0x7e, 0x92,
        0x35, 0xdc, 0x08, 0x4a, 0xb1, 0xb9, 0xcf, 0xa2, 0xf7, 0x36,
    };
    const uint8_t enc[] = {
        0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28, 0xe8, 0x86, 0x68,
        0xc3, 0xc8, 0xd7, 0xe9, 0x7d, 0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea,
        0x6d, 0x44, 0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31,
    };
    const uint8_t shared_secret[] = {
        0xfe, 0x0e, 0x18, 0xc9, 0xf0, 0x24, 0xce, 0x43, 0x79, 0x9a, 0xe3,
        0x93, 0xc7, 0xe8, 0xfe, 0x8f, 0xce, 0x9d, 0x21, 0x88, 0x75, 0xe8,
        0x22, 0x7b, 0x01, 0x87, 0xc0, 0x4e, 0x7d, 0x2e, 0xa1, 0xfc,
    };
    const uint8_t key[] = {
        0x45, 0x31, 0x68, 0x5d, 0x41, 0xd6, 0x5f, 0x3,
        0xdc, 0x48, 0xf6, 0xb8, 0x30, 0x2c, 0x5,  0xb0,
    };
    const uint8_t nonce[] = {
        0x56, 0xd8, 0x90, 0xe5, 0xac, 0xca, 0xaf, 0x1, 0x1c, 0xff, 0x4b, 0x7d,
    };
    const uint8_t exporter_secret[] = {
        0x45, 0xff, 0x1c, 0x2e, 0x22, 0xd,  0xb5, 0x87, 0x17, 0x19, 0x52,
        0xc0, 0x59, 0x2d, 0x5f, 0x5e, 0xbe, 0x10, 0x3f, 0x15, 0x61, 0xa2,
        0x61, 0x4e, 0x38, 0xf2, 0xff, 0xd4, 0x7e, 0x99, 0xe3, 0xf8,
    };

    hpke_t suite = {
        .mode = HPKE_MODE_BASE,
        .kem_id = HPKE_KEM_DHKEM_X25519,
        .kdf_id = HPKE_KDF_SHA256,
        .aead_id = HPKE_AEAD_AES128_GCM,
    };

    uint8_t test_enc[SIZEA(enc)];
    uint8_t test_ssSend[SIZEA(shared_secret)];
    uint8_t test_ssRecv[SIZEA(shared_secret)];

    if (HPKE_Encap_internal(HPKE_KEM_DHKEM_X25519, pkR, test_ssSend, test_enc,
                            skE, pkE))
        return 0;
    if (HPKE_Decap(HPKE_KEM_DHKEM_X25519, skR, test_enc, test_ssRecv))
        return 0;

    hpke_ctx_t ctx;
    hpke_array_ref_t info_Ref = {.b = info, .s = SIZEA(info)};
    hpke_array_ref_t ssSend_Ref = {.b = test_ssSend, .s = SIZEA(shared_secret)};
    hpke_array_ref_t empty = {NULL, 0};
    HPKE_KeySchedule(suite, ssSend_Ref, info_Ref, empty, empty, &ctx);

    int res = 1;
    res &= (memcmp(enc, test_enc, sizeof(enc)) == 0) ? 1 : 0;
    res &= (memcmp(shared_secret, test_ssSend, sizeof(shared_secret)) == 0) ? 1
                                                                            : 0;
    res &= (memcmp(shared_secret, test_ssRecv, sizeof(shared_secret)) == 0) ? 1
                                                                            : 0;
    res &= (memcmp(key, ctx.key, sizeof(key)) == 0) ? 1 : 0;
    res &= (memcmp(nonce, ctx.base_nonce, sizeof(nonce)) == 0) ? 1 : 0;
    res &= (memcmp(exporter_secret, ctx.exporter_secret, sizeof(key)) == 0) ? 1
                                                                            : 0;
    return res;
}

typedef struct {
    const char* name;
    int (*function)(void*);
    void* data;
} Test;

int main() {
    const Test tests[] = {
        {"test_hkdf_sha256", test_hkdf_sha256, NULL},
        {"test_aead_chacha20_poly1305", test_aead_chacha20_poly1305, NULL},
        {"test_aead_cp_endec", test_aead_cp_endec, NULL},
        {"test_hpke_encap", test_hpke_encap, NULL},
        {"test_hpke_auth_encap", test_hpke_auth_encap, NULL},
        {"test_hpke_setup_base", test_hpke_setup_base, NULL},
        {"test_hpke_setup_auth", test_hpke_setup_auth, NULL},
        {"test_hpke_seal_open", test_hpke_seal_open, NULL},
        {"test_dh_nist512", test_dh_nist512, NULL},
        {"test_rfc9180_a1", test_rfc9180_a1, NULL},
    };

    for (int i = 0; i < SIZEA(tests); i++) {
        const Test* const t = &tests[i];
        printf("%s", t->name);
        if (!t->function(t->data)) {
            printf(" FAIL\n");
            return 1;
        } else {
            printf(" PASS\n");
        }
    }

    return 0;
}