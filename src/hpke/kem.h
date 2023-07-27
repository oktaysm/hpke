#pragma once

#include <stdint.h>

int32_t kem_x25519_keygen(uint16_t kem, uint8_t* sk, uint8_t* pk);
int32_t kem_x25519_derive(uint16_t kem, const uint8_t* sk, uint8_t* pk);
int32_t kem_x25519_dh(uint16_t kem, const uint8_t* sk, const uint8_t* pk,
                      uint8_t* dh);

int32_t kem_nist_keygen(uint16_t kem, uint8_t* sk, uint8_t* pk);
int32_t kem_nist_derive(uint16_t kem, const uint8_t* sk, uint8_t* pk);
int32_t kem_nist_dh(uint16_t kem, const uint8_t* sk, const uint8_t* pk,
                    uint8_t* dh);
