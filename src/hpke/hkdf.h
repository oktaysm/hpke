#pragma once

#include <stdint.h>

int32_t hkdf_extract(uint16_t kdf_id, const uint8_t* salt, uint32_t salt_bytes,
                     const uint8_t* ikm, uint32_t ikm_bytes, uint8_t* md);
int32_t hkdf_expand(uint16_t kdf_id, const uint8_t* prk, uint32_t prk_bytes,
                    const uint8_t* info, uint32_t info_bytes, uint8_t* okm,
                    uint32_t okm_bytes);
