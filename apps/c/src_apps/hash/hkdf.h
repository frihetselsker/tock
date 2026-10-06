#pragma once

#include <stdint.h>
#include <libtock/tock.h>
#include "hash.h"

bool libtock_hkdf_exists(void);

typedef void (*libtock_hkdf_callback_done)(returncode_t);

returncode_t libtocksync_hkdf_compute(libtock_hash_algorithm_t hkdf_algorithm,
                                        uint8_t* ikm_buffer, uint32_t ikm_length,
                                        uint8_t* salt_buffer, uint32_t salt_length,
                                        uint8_t* info_buffer, uint32_t info_length,
                                        uint8_t* prk_buffer, uint32_t prk_length,
                                        uint8_t* okm_buffer, uint32_t okm_length);

returncode_t libtock_hkdf_compute(libtock_hash_algorithm_t hkdf_algorithm,
                                     uint8_t* ikm_buffer, uint32_t ikm_length,
                                     uint8_t* salt_buffer, uint32_t salt_length,
                                     uint8_t* info_buffer, uint32_t info_length,
                                     uint8_t* prk_buffer, uint32_t prk_length,
                                     uint8_t* okm_buffer, uint32_t okm_length,
                                     libtock_hkdf_callback_done cb);
