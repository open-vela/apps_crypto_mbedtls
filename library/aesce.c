/*
 *  Arm64 crypto engine support functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <string.h>
#include "common.h"

#if defined(MBEDTLS_AESCE_C)

#include "aesce.h"

#if defined(MBEDTLS_HAVE_ARM64)

#if defined(__clang__)
#   if __clang_major__ < 4
#       error "A more recent Clang is required for MBEDTLS_AES_C"
#   endif
#elif defined(__GNUC__)
#   if __GNUC__ < 6
#       error "A more recent GCC is required for MBEDTLS_AES_C"
#   endif
#else
#    error "Only GCC and Clang supported for MBEDTLS_AES_C"
#endif

#if !defined(__ARM_FEATURE_CRYPTO)
#   error "`crypto` feature moddifier MUST be enabled for MBEDTLS_AESCE_C."
#   error "Typical option for GCC and Clang is `-march=armv8-a+crypto`."
#endif /* !__ARM_FEATURE_CRYPTO */

#include <arm_neon.h>

#if defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

/*
 * AES instruction support detection routine
 */
int mbedtls_aesce_has_support(void)
{
#if defined(__linux__)
    unsigned long auxval = getauxval(AT_HWCAP);
    return (auxval & (HWCAP_ASIMD | HWCAP_AES)) ==
           (HWCAP_ASIMD | HWCAP_AES);
#else
    /* Suppose aes instructions are supported. */
    return 1;
#endif
}

static uint8x16_t aesce_encrypt_block(uint8x16_t block,
                                      unsigned char *keys,
                                      int rounds)
{
    for (int i = 0; i < rounds - 1; i++) {
        block = vaeseq_u8(block, vld1q_u8(keys + i * 16));
        /* AES mix columns */
        block = vaesmcq_u8(block);
    }

    /* AES single round encryption */
    block = vaeseq_u8(block, vld1q_u8(keys + (rounds -1) * 16));

    /* Final Add (bitwise Xor) */
    block = veorq_u8(block, vld1q_u8(keys + rounds  * 16));

    return block;
}

static uint8x16_t aesce_decrypt_block(uint8x16_t block,
                                      unsigned char *keys,
                                      int rounds)
{

    for (int i = 0; i < rounds - 1; i++) {
        block = vaesdq_u8(block, vld1q_u8(keys + i * 16));
        /* AES inverse mix columns */
        block = vaesimcq_u8(block);
    }

    /* AES single round encryption */
    block = vaesdq_u8(block, vld1q_u8(keys + (rounds - 1) * 16));

    /* Final Add (bitwise Xor) */
    block = veorq_u8(block, vld1q_u8(keys + rounds * 16));

    return block;
}

/*
 * AES-ECB block en(de)cryption
 */
int mbedtls_aesce_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16])
{
    uint8x16_t block = vld1q_u8(&input[0]);
    unsigned char *keys = (unsigned char *) (ctx->buf + ctx->rk_offset);

    if (mode == MBEDTLS_AES_ENCRYPT) {
        block = aesce_encrypt_block(block, keys, ctx->nr);
    } else {
        block = aesce_decrypt_block(block, keys, ctx->nr);
    }
    vst1q_u8(&output[0], block);

    return 0;
}


/*
 * Compute decryption round keys from encryption round keys
 */
void mbedtls_aesce_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey,
                               int nr)
{
    int i, j;
    j = nr;
    vst1q_u8(invkey, vld1q_u8(fwdkey + j * 16));
    for (i = 1, j--; j > 0; i++, j--) {
        vst1q_u8(invkey + i * 16,
                 vaesimcq_u8(vld1q_u8(fwdkey + j * 16)));
    }
    vst1q_u8(invkey + i * 16, vld1q_u8(fwdkey + j * 16));

}

static uint8_t const rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                0x20, 0x40, 0x80, 0x1b, 0x36 };

static inline uint32_t ror32_8(uint32_t word)
{
    return (word << (32 - 8)) | (word >> 8);
}

static inline uint32_t aes_sub(uint32_t in)
{
    uint32x4_t _in = vdupq_n_u32(in);
    uint32x4_t v;
    uint8x16_t zero = vdupq_n_u8(0);
    v = vreinterpretq_u32_u8(vaeseq_u8(zero, vreinterpretq_u8_u32(_in)));
    return vgetq_lane_u32(v, 0);
}

/*
 * Key expansion, 128-bit case
 */
static void aesce_setkey_enc_128(unsigned char *rk,
                                 const unsigned char *key)
{
    uint32_t *rki;
    uint32_t *rko;
    uint32_t *rk_u32 = (uint32_t *) rk;
    memcpy(rk, key, (128 / 8));

    for (size_t i = 0; i < sizeof(rcon); i++) {
        rki = rk_u32 + i * (128 / 32);
        rko = rki + (128 / 32);
        rko[0] = ror32_8(aes_sub(rki[(128 / 32) - 1])) ^ rcon[i] ^ rki[0];
        rko[1] = rko[0] ^ rki[1];
        rko[2] = rko[1] ^ rki[2];
        rko[3] = rko[2] ^ rki[3];
    }
}

/*
 * Key expansion, 192-bit case
 */
static void aesce_setkey_enc_192(unsigned char *rk,
                                 const unsigned char *key)
{
    uint32_t *rki;
    uint32_t *rko;
    uint32_t *rk_u32 = (uint32_t *) rk;
    memcpy(rk, key, (192 / 8));

    for (size_t i = 0; i < 8; i++) {
        rki = rk_u32 + i * (192 / 32);
        rko = rki + (192 / 32);
        rko[0] = ror32_8(aes_sub(rki[(192 / 32) - 1])) ^ rcon[i] ^ rki[0];
        rko[1] = rko[0] ^ rki[1];
        rko[2] = rko[1] ^ rki[2];
        rko[3] = rko[2] ^ rki[3];
        if (i < 7) {
            rko[4] = rko[3] ^ rki[4];
            rko[5] = rko[4] ^ rki[5];
        }
    }
}

/*
 * Key expansion, 256-bit case
 */
static void aesce_setkey_enc_256(unsigned char *rk,
                                 const unsigned char *key)
{
    uint32_t *rki;
    uint32_t *rko;
    uint32_t *rk_u32 = (uint32_t *) rk;
    memcpy(rk, key, (256 / 8));

    for (size_t i = 0; i < 7; i++) {
        rki = rk_u32 + i * (256 / 32);
        rko = rki + (256 / 32);
        rko[0] = ror32_8(aes_sub(rki[(256 / 32) - 1])) ^ rcon[i] ^ rki[0];
        rko[1] = rko[0] ^ rki[1];
        rko[2] = rko[1] ^ rki[2];
        rko[3] = rko[2] ^ rki[3];
        if (i < 6) {
            rko[4] = aes_sub(rko[3]) ^ rki[4];
            rko[5] = rko[4] ^ rki[5];
            rko[6] = rko[5] ^ rki[6];
            rko[7] = rko[6] ^ rki[7];
        }
    }
}

/*
 * Key expansion, wrapper
 */
int mbedtls_aesce_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits)
{
    switch (bits) {
        case 128: aesce_setkey_enc_128(rk, key); break;
        case 192: aesce_setkey_enc_192(rk, key); break;
        case 256: aesce_setkey_enc_256(rk, key); break;
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    return 0;
}

#endif /* MBEDTLS_HAVE_ARM64 */

#endif /* MBEDTLS_AESCE_C */