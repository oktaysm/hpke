#pragma once

#include <stdint.h>

int32_t aead_seal(uint16_t aead_id, const uint8_t *key, const uint8_t *nonce,
                  uint32_t aad_bytes, const uint8_t *aad, uint32_t in_bytes,
                  const uint8_t *in, uint32_t out_bytes, uint8_t *out);
int32_t aead_open(uint16_t aead_id, const uint8_t *key, const uint8_t *nonce,
                  uint32_t aad_bytes, const uint8_t *aad, uint32_t in_bytes,
                  const uint8_t *in, uint32_t out_bytes, uint8_t *out);
