#pragma once

#include <stdint.h>
#include <hpke/hpke.h>

typedef struct {
    char *kem;
    uint8_t id;
} hpke_mode_t;

typedef struct {
    char *kem;
    uint16_t id;
    uint16_t Nsecret;
    uint16_t Nenc;
    uint16_t Npk;
    uint16_t Nsk;
    uint16_t Ukdf_id;
    int32_t (*UKeygen)(uint16_t, uint8_t *, uint8_t *);
    int32_t (*UDerive)(uint16_t, const uint8_t *, uint8_t *);
    int32_t (*UDH)(uint16_t, const uint8_t *, const uint8_t *, uint8_t *);
} hpke_kem_t;

typedef struct {
    char *kdf;
    uint16_t id;
    uint16_t Nh;
    int32_t (*Uextract)(uint16_t, const uint8_t *, uint32_t, const uint8_t *,
                        uint32_t, uint8_t *);
    int32_t (*Uexpand)(uint16_t, const uint8_t *, uint32_t, const uint8_t *,
                       uint32_t, uint8_t *, uint32_t);
} hpke_kdf_t;

typedef struct {
    char *aead;
    uint16_t id;
    uint16_t Nk;
    uint16_t Nn;
    uint16_t Nt;
    int32_t (*Useal)(uint16_t, const uint8_t *, const uint8_t *, uint32_t,
                     const uint8_t *, uint32_t, const uint8_t *, uint32_t,
                     uint8_t *);
    int32_t (*Uopen)(uint16_t, const uint8_t *, const uint8_t *, uint32_t,
                     const uint8_t *, uint32_t, const uint8_t *, uint32_t,
                     uint8_t *);
} hpke_aead_t;

extern const hpke_mode_t modes[];
extern const hpke_kem_t kems[];
extern const hpke_kdf_t kdf[];
extern const hpke_aead_t aeads[];

int32_t HPKE_KeySchedule(hpke_t suite, hpke_array_ref_t shared_secret,
                         hpke_array_ref_t info, hpke_array_ref_t psk,
                         hpke_array_ref_t psk_id, hpke_ctx_t *ctx);

int32_t HPKE_Encap_internal(uint32_t kem_id, const uint8_t *pkR,
                            uint8_t *shared_secret, uint8_t *enc,
                            const uint8_t *eppSk, const uint8_t *eppPk);

int32_t HPKE_AuthEncap_internal(uint32_t kem_id, const uint8_t *pkR,
                                const uint8_t *skS, uint8_t *shared_secret,
                                uint8_t *enc, const uint8_t *eppSk,
                                const uint8_t *eppPk);