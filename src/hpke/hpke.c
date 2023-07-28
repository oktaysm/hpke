#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <hpke/utils.h>
#include <hpke/hkdf.h>
#include <hpke/aead.h>
#include <hpke/hpke_locl.h>
#include <hpke/hpke.h>
#include <hpke/kem.h>

typedef struct {
    uint32_t s;
    hpke_array_ref_t *a[0x10];
} Arrays_t;

static inline uint32_t Arrays_Size(Arrays_t *as) {
    uint32_t res = 0;
    for (int i = 0; i < as->s; i++) {
        res += as->a[i]->s;
    }
    return res;
}

static inline uint32_t Arrays_Export(Arrays_t *as, uint8_t *out,
                                     uint32_t limit) {
    uint32_t res = Arrays_Size(as);
    assert(res <= limit);
    res = 0;
    for (int i = 0; i < as->s; i++) {
        if (as->a[i]->s && as->a[i]->b != NULL) {
            memcpy(out + res, as->a[i]->b, as->a[i]->s * sizeof(uint8_t));
            res += as->a[i]->s;
        }
    }
    return res;
}

uint32_t ArrayRef_Concat(uint8_t *out, uint32_t limit, uint32_t arg_count,
                         ...) {
    va_list ap;
    Arrays_t as;
    assert(arg_count <= 0x10);
    va_start(ap, arg_count);

    for (int i = 0; i < arg_count; i++) {
        hpke_array_ref_t *ba = va_arg(ap, hpke_array_ref_t *);
        as.a[i] = ba;
    }
    as.s = arg_count;
    va_end(ap);
    return Arrays_Export(&as, out, limit);
}

const hpke_mode_t modes[] = {
    {
        .id = 0x00,
        .kem = "mode_base",
    },
    {
        .id = 0x01,
        .kem = "mode_psk",
    },
    {
        .id = 0x02,
        .kem = "mode_auth",
    },
    {
        .id = 0x03,
        .kem = "mode_auth_psk",
    },
};

const hpke_kem_t kems[] = {
    {
        .id = 0x0010,
        .kem = "DHKEM(P-256, HKDF-SHA256)",
        .Nsecret = 32,
        .Nenc = 65,
        .Npk = 65,
        .Nsk = 32,
        .Ukdf_id = HPKE_KDF_SHA256,
        .UKeygen = kem_nist_keygen,
        .UDerive = kem_nist_derive,
        .UDH = kem_nist_dh,
    },
    {
        .id = 0x0011,
        .kem = "DHKEM(P-384, HKDF-SHA384)",
        .Nsecret = 48,
        .Nenc = 97,
        .Npk = 97,
        .Nsk = 48,
        .Ukdf_id = HPKE_KDF_SHA384,
        .UKeygen = kem_nist_keygen,
        .UDerive = kem_nist_derive,
        .UDH = kem_nist_dh,
    },
    {
        .id = 0x0012,
        .kem = "DHKEM(P-521, HKDF-SHA512)",
        .Nsecret = 64,
        .Nenc = 133,
        .Npk = 133,
        .Nsk = 66,
        .Ukdf_id = HPKE_KDF_SHA512,
        .UKeygen = kem_nist_keygen,
        .UDerive = kem_nist_derive,
        .UDH = kem_nist_dh,
    },
    {
        .id = 0x0020,
        .kem = "DHKEM(X25519, HKDF-SHA256)",
        .Nsecret = 32,
        .Nenc = 32,
        .Npk = 32,
        .Nsk = 32,
        .Ukdf_id = HPKE_KDF_SHA256,
        .UKeygen = kem_x25519_keygen,
        .UDerive = kem_x25519_derive,
        .UDH = kem_x25519_dh,
    },
    {
        .id = 0x0021,
        .kem = "DHKEM(X448, HKDF-SHA512)",
        .Nsecret = 64,
        .Nenc = 56,
        .Npk = 56,
        .Nsk = 56,
        .Ukdf_id = HPKE_KDF_SHA512,
        .UKeygen = NULL,
        .UDerive = NULL,
        .UDH = NULL,
    },
};

const hpke_kdf_t kdf[] = {
    {
        .id = 0x0001,
        .kdf = "HKDF-SHA256",
        .Nh = 32,
        .Uextract = hkdf_extract,
        .Uexpand = hkdf_expand,
    },
    {
        .id = 0x0002,
        .kdf = "HKDF-SHA384",
        .Nh = 48,
        .Uextract = hkdf_extract,
        .Uexpand = hkdf_expand,
    },
    {
        .id = 0x0003,
        .kdf = "HKDF-SHA512",
        .Nh = 64,
        .Uextract = hkdf_extract,
        .Uexpand = hkdf_expand,
    },
};

const hpke_aead_t aeads[] = {
    {
        .id = 0x0001,
        .aead = "AES-128-GCM",
        .Nk = 16,
        .Nn = 12,
        .Nt = 16,
        .Useal = aead_seal,
        .Uopen = aead_open,
    },
    {
        .id = 0x0002,
        .aead = "AES-256-GCM",
        .Nk = 32,
        .Nn = 12,
        .Nt = 16,
        .Useal = aead_seal,
        .Uopen = aead_open,
    },
    {
        .id = 0x0003,
        .aead = "ChaCha20Poly1305",
        .Nk = 32,
        .Nn = 12,
        .Nt = 16,
        .Useal = aead_seal,
        .Uopen = aead_open,
    },
};

int32_t HPKE_LExtract(uint32_t kdf_id, hpke_array_ref_t salt,
                      hpke_array_ref_t suite_text, hpke_array_ref_t label,
                      hpke_array_ref_t ikm, uint8_t *out) {
    uint8_t hpke[7] = "HPKE-v1";

    hpke_array_ref_t hpke_Ref = {hpke, 7};

    uint8_t likm[hpke_Ref.s + suite_text.s + label.s + ikm.s];
    uint32_t likm_size = ArrayRef_Concat(likm, SIZEA(likm), 4, &hpke_Ref,
                                         &suite_text, &label, &ikm);
    return kdf[kdf_id].Uextract(kdf_id, salt.b, salt.s, likm, likm_size, out);
}

int32_t HPKE_LExpand(uint32_t kdf_id, hpke_array_ref_t prk,
                     hpke_array_ref_t suite_text, hpke_array_ref_t label,
                     hpke_array_ref_t info, uint32_t L, uint8_t *out) {
    uint8_t l_be[2];
    uint8_t hpke[7] = "HPKE-v1";
    sbe16(L & 0x0000ffff, l_be);

    hpke_array_ref_t l_Ref = {l_be, 2};
    hpke_array_ref_t hpke_Ref = {hpke, 7};

    uint8_t linfo[l_Ref.s + hpke_Ref.s + suite_text.s + label.s + info.s];
    uint32_t linfo_size = ArrayRef_Concat(
        linfo, SIZEA(linfo), 5, &l_Ref, &hpke_Ref, &suite_text, &label, &info);
    return kdf[kdf_id].Uexpand(kdf_id, prk.b, prk.s, linfo, linfo_size, out, L);
}

int32_t HPKE_ExtractAndExpand(uint32_t kem_id, hpke_array_ref_t dh,
                              hpke_array_ref_t kem, uint8_t *shared_secret) {
    uint32_t kdf_id = kems[kem_id].Ukdf_id;
    uint8_t eae_prk[kdf[kdf_id].Nh];
    uint8_t suite_text[5] = "KEM";
    sbe16(kems[kem_id].id & 0x0000ffff, suite_text + 3);

    hpke_array_ref_t salt_Ref = {(const uint8_t *)0x0, 0};
    hpke_array_ref_t label_Ref = {(const uint8_t *)"eae_prk", 7};
    hpke_array_ref_t lbl_Ref = {(const uint8_t *)"shared_secret", 13};
    hpke_array_ref_t eae_prk_Ref = {eae_prk, SIZEA(eae_prk)};
    hpke_array_ref_t suite_text_Ref = {suite_text, 5};

    if (HPKE_LExtract(kdf_id, salt_Ref, suite_text_Ref, label_Ref, dh, eae_prk))
        return -1;
    if (HPKE_LExpand(kdf_id, eae_prk_Ref, suite_text_Ref, lbl_Ref, kem,
                     kems[kem_id].Nsecret, shared_secret))
        return -1;
    return 0;
}

int32_t HPKE_Encap_internal(uint32_t kem_id, const uint8_t *pkR,
                            uint8_t *shared_secret, uint8_t *enc,
                            const uint8_t *eppSk, const uint8_t *eppPk) {
    uint8_t epSk[kems[kem_id].Nsk], epPk[kems[kem_id].Npk];
    uint8_t dh[kems[kem_id].Nsk];
    uint8_t kem[kems[kem_id].Nenc + kems[kem_id].Npk];

    if (eppSk == NULL) {
        if (kems[kem_id].UKeygen(kem_id, epSk, epPk))
            goto err;
    } else {
        memcpy(epSk, eppSk, kems[kem_id].Nsk * sizeof(uint8_t));
        memcpy(epPk, eppPk, kems[kem_id].Npk * sizeof(uint8_t));
    }

    if (kems[kem_id].UDH(kem_id, epSk, pkR, dh))
        goto err;

    memcpy(enc, epPk, kems[kem_id].Nenc * sizeof(uint8_t));

    hpke_array_ref_t pkR_Ref = {pkR, kems[kem_id].Npk};
    hpke_array_ref_t enc_Ref = {enc, kems[kem_id].Nenc};
    hpke_array_ref_t dh_Ref = {dh, SIZEA(dh)};

    uint32_t kemsize = ArrayRef_Concat(kem, SIZEA(kem), 2, &enc_Ref, &pkR_Ref);
    hpke_array_ref_t kem_Ref = {kem, kemsize};
    if (HPKE_ExtractAndExpand(kem_id, dh_Ref, kem_Ref, shared_secret))
        goto err;
    explicit_bzero(&dh, sizeof(dh));
    explicit_bzero(&epSk, sizeof(epSk));
    return 0;
err:
    explicit_bzero(&dh, sizeof(dh));
    explicit_bzero(&epSk, sizeof(epSk));
    return -1;
}
DLL_PUBLIC int32_t HPKE_Encap(uint32_t kem_id, const uint8_t *pkR,
                              uint8_t *shared_secret, uint8_t *enc) {
    return HPKE_Encap_internal(kem_id, pkR, shared_secret, enc, NULL, NULL);
}

int32_t HPKE_AuthEncap_internal(uint32_t kem_id, const uint8_t *pkR,
                                const uint8_t *skS, uint8_t *shared_secret,
                                uint8_t *enc, const uint8_t *eppSk,
                                const uint8_t *eppPk) {
    uint8_t epSk[kems[kem_id].Nsk], epPk[kems[kem_id].Npk];
    uint8_t dh[kems[kem_id].Nsk * 2];
    uint8_t kem[kems[kem_id].Nenc + kems[kem_id].Npk * 2];
    uint8_t pkS[kems[kem_id].Npk];

    if (eppSk == NULL) {
        if (kems[kem_id].UKeygen(kem_id, epSk, epPk))
            goto err;
    } else {
        memcpy(epSk, eppSk, kems[kem_id].Nsk * sizeof(uint8_t));
        memcpy(epPk, eppPk, kems[kem_id].Npk * sizeof(uint8_t));
    }

    if (kems[kem_id].UDH(kem_id, epSk, pkR, dh))
        goto err;
    if (kems[kem_id].UDH(kem_id, skS, pkR, dh + kems[kem_id].Nsk))
        goto err;
    if (kems[kem_id].UDerive(kem_id, skS, pkS))
        goto err;

    memcpy(enc, epPk, kems[kem_id].Nenc * sizeof(uint8_t));

    hpke_array_ref_t enc_Ref = {enc, kems[kem_id].Nenc};
    hpke_array_ref_t dh_Ref = {dh, SIZEA(dh)};
    hpke_array_ref_t pkS_Ref = {pkS, SIZEA(pkS)};
    hpke_array_ref_t pkR_Ref = {pkR, kems[kem_id].Npk};

    uint32_t kemsize =
        ArrayRef_Concat(kem, SIZEA(kem), 3, &enc_Ref, &pkR_Ref, &pkS_Ref);
    hpke_array_ref_t kem_Ref = {kem, kemsize};
    if (HPKE_ExtractAndExpand(kem_id, dh_Ref, kem_Ref, shared_secret))
        goto err;

    explicit_bzero(&dh, sizeof(dh));
    explicit_bzero(&epSk, sizeof(epSk));
    return 0;
err:
    explicit_bzero(&dh, sizeof(dh));
    explicit_bzero(&epSk, sizeof(epSk));
    return -1;
}
DLL_PUBLIC int32_t HPKE_AuthEncap(uint32_t kem_id, const uint8_t *pkR,
                                  const uint8_t *skS, uint8_t *shared_secret,
                                  uint8_t *enc) {
    return HPKE_AuthEncap_internal(kem_id, pkR, skS, shared_secret, enc, NULL,
                                   NULL);
}

DLL_PUBLIC int32_t HPKE_Decap(uint32_t kem_id, const uint8_t *skR,
                              const uint8_t *enc, uint8_t *shared_secret) {
    uint8_t dh[kems[kem_id].Nsk];
    uint8_t pkR[kems[kem_id].Npk];
    uint8_t kem[kems[kem_id].Nenc + kems[kem_id].Npk];
    if (kems[kem_id].UDerive(kem_id, skR, pkR))
        goto err;
    if (kems[kem_id].UDH(kem_id, skR, enc, dh))
        goto err;

    hpke_array_ref_t enc_Ref = {enc, kems[kem_id].Nenc};
    hpke_array_ref_t pkR_Ref = {pkR, kems[kem_id].Npk};
    hpke_array_ref_t dh_Ref = {dh, SIZEA(dh)};

    uint32_t kemsize = ArrayRef_Concat(kem, SIZEA(kem), 2, &enc_Ref, &pkR_Ref);
    hpke_array_ref_t kem_Ref = {kem, kemsize};
    if (HPKE_ExtractAndExpand(kem_id, dh_Ref, kem_Ref, shared_secret))
        goto err;
    explicit_bzero(&dh, sizeof(dh));
    return 0;
err:
    explicit_bzero(&dh, sizeof(dh));
    return -1;
}

DLL_PUBLIC int32_t HPKE_AuthDecap(uint32_t kem_id, const uint8_t *skR,
                                  const uint8_t *pkS, const uint8_t *enc,
                                  uint8_t *shared_secret) {
    uint8_t dh[kems[kem_id].Nsk * 2];
    uint8_t pkR[kems[kem_id].Npk];
    uint8_t kem[kems[kem_id].Nenc + kems[kem_id].Npk * 2];
    if (kems[kem_id].UDerive(kem_id, skR, pkR))
        goto err;
    if (kems[kem_id].UDH(kem_id, skR, enc, dh))
        goto err;
    if (kems[kem_id].UDH(kem_id, skR, pkS, dh + kems[kem_id].Nsk))
        goto err;

    hpke_array_ref_t enc_Ref = {enc, kems[kem_id].Nenc};
    hpke_array_ref_t pkR_Ref = {pkR, kems[kem_id].Npk};
    hpke_array_ref_t pkS_Ref = {pkS, kems[kem_id].Npk};
    hpke_array_ref_t dh_Ref = {dh, SIZEA(dh)};

    uint32_t kemsize =
        ArrayRef_Concat(kem, SIZEA(kem), 3, &enc_Ref, &pkR_Ref, &pkS_Ref);
    hpke_array_ref_t kem_Ref = {kem, kemsize};
    if (HPKE_ExtractAndExpand(kem_id, dh_Ref, kem_Ref, shared_secret))
        goto err;
    explicit_bzero(&dh, sizeof(dh));
    return 0;
err:
    explicit_bzero(&dh, sizeof(dh));
    return -1;
}

int32_t HPKE_KeySchedule(hpke_t suite, hpke_array_ref_t shared_secret,
                         hpke_array_ref_t info, hpke_array_ref_t psk,
                         hpke_array_ref_t psk_id, hpke_ctx_t *ctx) {
    uint8_t modee;
    uint8_t suite_text[10] = "HPKE";
    sbe16(kems[suite.kem_id].id & 0x0000ffff, suite_text + 4);
    sbe16(kdf[suite.kdf_id].id & 0x0000ffff, suite_text + 6);
    sbe16(aeads[suite.aead_id].id & 0x0000ffff, suite_text + 8);
    modee = modes[suite.mode].id & 0xff;

    uint8_t psk_id_hash[kdf[suite.kdf_id].Nh];
    uint8_t info_hash[kdf[suite.kdf_id].Nh];
    uint8_t secret[kdf[suite.kdf_id].Nh];
    uint8_t ksc[1 + 2 * kdf[suite.kdf_id].Nh];

    hpke_array_ref_t mode_Ref = {&modee, 1};
    hpke_array_ref_t suite_text_Ref = {suite_text, 10};
    hpke_array_ref_t salt_Ref = {(const uint8_t *)0x0, 0};

    hpke_array_ref_t label_info_hash_Ref = {(const uint8_t *)"info_hash", 9};
    hpke_array_ref_t label_psk_id_hash_Ref = {(const uint8_t *)"psk_id_hash",
                                              11};
    hpke_array_ref_t label_secret_Ref = {(const uint8_t *)"secret", 6};
    hpke_array_ref_t label_key_Ref = {(const uint8_t *)"key", 3};
    hpke_array_ref_t label_base_nonce_Ref = {(const uint8_t *)"base_nonce", 10};
    hpke_array_ref_t label_exp_Ref = {(const uint8_t *)"exp", 3};

    hpke_array_ref_t psk_id_hash_Ref = {psk_id_hash, SIZEA(psk_id_hash)};
    hpke_array_ref_t info_hash_Ref = {info_hash, SIZEA(info_hash)};
    hpke_array_ref_t ksc_Ref = {ksc, SIZEA(ksc)};
    hpke_array_ref_t secret_Ref = {secret, SIZEA(secret)};

    if (HPKE_LExtract(suite.kdf_id, salt_Ref, suite_text_Ref,
                      label_psk_id_hash_Ref, psk_id, psk_id_hash))
        goto err;
    if (HPKE_LExtract(suite.kdf_id, salt_Ref, suite_text_Ref,
                      label_info_hash_Ref, info, info_hash))
        goto err;
    if (HPKE_LExtract(suite.kdf_id, shared_secret, suite_text_Ref,
                      label_secret_Ref, psk, secret))
        goto err;
    ArrayRef_Concat(ksc, SIZEA(ksc), 3, &mode_Ref, &psk_id_hash_Ref,
                    &info_hash_Ref);

    memset(ctx->key, 0, sizeof(ctx->key));
    if (HPKE_LExpand(suite.kdf_id, secret_Ref, suite_text_Ref, label_key_Ref,
                     ksc_Ref, aeads[suite.aead_id].Nk, ctx->key))
        goto err;
    if (HPKE_LExpand(suite.kdf_id, secret_Ref, suite_text_Ref,
                     label_base_nonce_Ref, ksc_Ref, aeads[suite.aead_id].Nn,
                     ctx->base_nonce))
        goto err;
    if (HPKE_LExpand(suite.kdf_id, secret_Ref, suite_text_Ref, label_exp_Ref,
                     ksc_Ref, kdf[suite.kdf_id].Nh, ctx->exporter_secret))
        goto err;
    ctx->seq = 0;
    ctx->suite.kem_id = suite.kem_id;
    ctx->suite.kdf_id = suite.kdf_id;
    ctx->suite.aead_id = suite.aead_id;
    ctx->suite.mode = suite.mode;

    explicit_bzero(&psk_id_hash, sizeof(psk_id_hash));
    explicit_bzero(&info_hash, sizeof(info_hash));
    explicit_bzero(&secret, sizeof(secret));
    explicit_bzero(&ksc, sizeof(ksc));
    return 0;
err:
    explicit_bzero(&psk_id_hash, sizeof(psk_id_hash));
    explicit_bzero(&info_hash, sizeof(info_hash));
    explicit_bzero(&secret, sizeof(secret));
    explicit_bzero(&ksc, sizeof(ksc));
    return -1;
}

DLL_PUBLIC int32_t HPKE_SetupS(hpke_t suite, const uint8_t *pkR,
                               hpke_array_ref_t info, hpke_array_ref_t psk,
                               hpke_array_ref_t psk_id, uint8_t *enc,
                               hpke_ctx_t *ctx) {
    uint8_t shared_secret[kems[suite.kem_id].Nsecret];
    hpke_array_ref_t empty = {NULL, 0};
    hpke_array_ref_t ss_Ref = {shared_secret, SIZEA(shared_secret)};

    if (HPKE_Encap(suite.kem_id, pkR, shared_secret, enc))
        goto err;
    if (HPKE_KeySchedule(suite, ss_Ref, info, empty, empty, ctx))
        goto err;
    explicit_bzero(&shared_secret, sizeof(shared_secret));
    return 0;
err:
    explicit_bzero(&shared_secret, sizeof(shared_secret));
    return -1;
}

DLL_PUBLIC int32_t HPKE_SetupR(hpke_t suite, const uint8_t *enc,
                               const uint8_t *skR, hpke_array_ref_t info,
                               hpke_array_ref_t psk, hpke_array_ref_t psk_id,
                               hpke_ctx_t *ctx) {
    uint8_t shared_secret[kems[suite.kem_id].Nsecret];
    hpke_array_ref_t ss_Ref = {shared_secret, SIZEA(shared_secret)};

    if (HPKE_Decap(suite.kem_id, skR, enc, shared_secret))
        goto err;
    if (HPKE_KeySchedule(suite, ss_Ref, info, psk, psk_id, ctx))
        goto err;
    explicit_bzero(&shared_secret, sizeof(shared_secret));
    return 0;
err:
    explicit_bzero(&shared_secret, sizeof(shared_secret));
    return -1;
}

DLL_PUBLIC int32_t HPKE_SetupAuthS(hpke_t suite, const uint8_t *pkR,
                                   const uint8_t *skS, hpke_array_ref_t info,
                                   hpke_array_ref_t psk,
                                   hpke_array_ref_t psk_id, uint8_t *enc,
                                   hpke_ctx_t *ctx) {
    uint8_t shared_secret[kems[suite.kem_id].Nsecret];
    hpke_array_ref_t ss_Ref = {shared_secret, SIZEA(shared_secret)};

    if (HPKE_AuthEncap(suite.kem_id, pkR, skS, shared_secret, enc))
        goto err;
    if (HPKE_KeySchedule(suite, ss_Ref, info, psk, psk_id, ctx))
        goto err;
    explicit_bzero(&shared_secret, sizeof(shared_secret));
    return 0;
err:
    explicit_bzero(&shared_secret, sizeof(shared_secret));
    return -1;
}

DLL_PUBLIC int32_t HPKE_SetupAuthR(hpke_t suite, const uint8_t *enc,
                                   const uint8_t *skR, const uint8_t *pkS,
                                   hpke_array_ref_t info, hpke_array_ref_t psk,
                                   hpke_array_ref_t psk_id, hpke_ctx_t *ctx) {
    uint8_t shared_secret[kems[suite.kem_id].Nsecret];
    hpke_array_ref_t ss_Ref = {shared_secret, SIZEA(shared_secret)};

    if (HPKE_AuthDecap(suite.kem_id, skR, pkS, enc, shared_secret))
        goto err;
    if (HPKE_KeySchedule(suite, ss_Ref, info, psk, psk_id, ctx))
        goto err;
    explicit_bzero(&shared_secret, sizeof(shared_secret));
    return 0;
err:
    explicit_bzero(&shared_secret, sizeof(shared_secret));
    return -1;
}

DLL_PUBLIC int32_t HPKE_Seal(hpke_ctx_t *ctx, hpke_array_ref_t aad,
                             hpke_array_ref_t plain, uint8_t *ct) {
    const hpke_aead_t *aead = &aeads[ctx->suite.aead_id];
    uint32_t nonce_size = aead->Nn;
    uint8_t cnonce[nonce_size];
    memset(cnonce, 0x0, nonce_size * sizeof(uint8_t));
    sbe64(ctx->seq, cnonce + nonce_size - 8);
    for (int i = 0; i < nonce_size; i++) {
        cnonce[i] = cnonce[i] ^ ctx->base_nonce[i];
    }

    if (aead->Useal(ctx->suite.aead_id, ctx->key, cnonce, aad.s, aad.b, plain.s,
                    plain.b, plain.s + aead->Nt, ct)) {
        explicit_bzero(&cnonce, sizeof(cnonce));
        return -1;
    }
    ctx->seq++;
    explicit_bzero(&cnonce, sizeof(cnonce));
    return 0;
}

DLL_PUBLIC int32_t HPKE_Open(hpke_ctx_t *ctx, hpke_array_ref_t aad,
                             hpke_array_ref_t ct, uint8_t *plain) {
    const hpke_aead_t *aead = &aeads[ctx->suite.aead_id];
    uint32_t nonce_size = aead->Nn;
    uint8_t cnonce[nonce_size];
    memset(cnonce, 0x0, nonce_size * sizeof(uint8_t));
    sbe64(ctx->seq, cnonce + nonce_size - 8);
    for (int i = 0; i < nonce_size; i++) {
        cnonce[i] = cnonce[i] ^ ctx->base_nonce[i];
    }

    if (aead->Uopen(ctx->suite.aead_id, ctx->key, cnonce, aad.s, aad.b, ct.s,
                    ct.b, ct.s - aead->Nt, plain)) {
        explicit_bzero(&cnonce, sizeof(cnonce));
        return -1;
    }
    ctx->seq++;
    explicit_bzero(&cnonce, sizeof(cnonce));
    return 0;
}

DLL_PUBLIC int32_t HPKE_Keysize(uint16_t kem_id, uint32_t *sk_size,
                                uint32_t *pk_size, uint32_t *ssecret_size) {
    if (pk_size)
        *pk_size = kems[kem_id].Npk;
    if (sk_size)
        *sk_size = kems[kem_id].Nsk;
    if (ssecret_size)
        *ssecret_size = kems[kem_id].Nsecret;
    return 0;
}

DLL_PUBLIC int32_t HPKE_Keygen(uint16_t kem_id, uint8_t *sk, uint8_t *pk) {
    return kems[kem_id].UKeygen(kem_id, sk, pk);
}

DLL_PUBLIC int32_t HPKE_Derive(uint16_t kem_id, const uint8_t *sk,
                               uint8_t *pk) {
    return kems[kem_id].UDerive(kem_id, sk, pk);
}
