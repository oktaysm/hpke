#pragma once

#include <stdint.h>

#define ROTL32(a, n) ((a << n) | (a >> (32 - n)))
#define ROTL64(a, n) ((a << n) | (a >> (64 - n)))

#define ROTR32(a, n) (((a) >> n) | (a) << (32 - n))
#define ROTR64(a, n) (((a) >> n) | (a) << (64 - n))

#define SIZEA(a) (sizeof((a)) / (sizeof((*a))))
#define CEIL(n, s) (((n) + (s)-1) / (s))

static inline uint32_t lle16(const uint8_t* const b) {
    return ((((uint16_t)b[0] << 0) & (0xffU << 0)) |
            (((uint16_t)b[1] << 8) & (0xffU << 8)));
}

static inline uint32_t lbe16(const uint8_t* const b) {
    return ((((uint16_t)b[1] << 0) & (0xffU << 0)) |
            (((uint16_t)b[0] << 8) & (0xffU << 8)));
}

static inline uint32_t lle32(const uint8_t* const b) {
    return ((((uint32_t)b[0] << 0) & (0xffU << 0)) |
            (((uint32_t)b[1] << 8) & (0xffU << 8)) |
            (((uint32_t)b[2] << 16) & (0xffU << 16)) |
            (((uint32_t)b[3] << 24) & (0xffU << 24)));
}

static inline uint32_t lbe32(const uint8_t* const b) {
    return ((((uint32_t)b[3] << 0) & (0xffU << 0)) |
            (((uint32_t)b[2] << 8) & (0xffU << 8)) |
            (((uint32_t)b[1] << 16) & (0xffU << 16)) |
            (((uint32_t)b[0] << 24) & (0xffU << 24)));
}

static inline uint64_t lle64(const uint8_t* const b) {
    return ((((uint64_t)b[0] << 0) & (0xffUL << 0)) |
            (((uint64_t)b[1] << 8) & (0xffUL << 8)) |
            (((uint64_t)b[2] << 16) & (0xffUL << 16)) |
            (((uint64_t)b[3] << 24) & (0xffUL << 24)) |
            (((uint64_t)b[4] << 32) & (0xffUL << 32)) |
            (((uint64_t)b[5] << 40) & (0xffUL << 40)) |
            (((uint64_t)b[6] << 48) & (0xffUL << 48)) |
            (((uint64_t)b[7] << 56) & (0xffUL << 56)));
}

static inline uint64_t lbe64(const uint8_t* const b) {
    return ((((uint64_t)b[7] << 0) & (0xffUL << 0)) |
            (((uint64_t)b[6] << 8) & (0xffUL << 8)) |
            (((uint64_t)b[5] << 16) & (0xffUL << 16)) |
            (((uint64_t)b[4] << 24) & (0xffUL << 24)) |
            (((uint64_t)b[3] << 32) & (0xffUL << 32)) |
            (((uint64_t)b[2] << 40) & (0xffUL << 40)) |
            (((uint64_t)b[1] << 48) & (0xffUL << 48)) |
            (((uint64_t)b[0] << 56) & (0xffUL << 56)));
}

static inline void sle16(uint16_t u, uint8_t* const c) {
    c[0] = (u >> 0) & 0xffU;
    c[1] = (u >> 8) & 0xffU;
}

static inline void sbe16(uint16_t u, uint8_t* const c) {
    c[0] = (u >> 8) & 0xffU;
    c[1] = (u >> 0) & 0xffU;
}

static inline void sle32(uint32_t u, uint8_t* const c) {
    c[0] = (u >> 0) & 0xffU;
    c[1] = (u >> 8) & 0xffU;
    c[2] = (u >> 16) & 0xffU;
    c[3] = (u >> 24) & 0xffU;
}

static inline void sbe32(uint32_t u, uint8_t* const c) {
    c[0] = (u >> 24) & 0xffU;
    c[1] = (u >> 16) & 0xffU;
    c[2] = (u >> 8) & 0xffU;
    c[3] = (u >> 0) & 0xffU;
}

static inline void sle64(uint64_t u, uint8_t* const c) {
    c[0] = (u >> 0) & 0xffUL;
    c[1] = (u >> 8) & 0xffUL;
    c[2] = (u >> 16) & 0xffUL;
    c[3] = (u >> 24) & 0xffUL;
    c[4] = (u >> 32) & 0xffUL;
    c[5] = (u >> 40) & 0xffUL;
    c[6] = (u >> 48) & 0xffUL;
    c[7] = (u >> 56) & 0xffUL;
}

static inline void sbe64(uint64_t u, uint8_t* const c) {
    c[0] = (u >> 56) & 0xffUL;
    c[1] = (u >> 48) & 0xffUL;
    c[2] = (u >> 40) & 0xffUL;
    c[3] = (u >> 32) & 0xffUL;
    c[4] = (u >> 24) & 0xffUL;
    c[5] = (u >> 16) & 0xffUL;
    c[6] = (u >> 8) & 0xffUL;
    c[7] = (u >> 0) & 0xffUL;
}
