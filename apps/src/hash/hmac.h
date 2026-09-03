
#pragma once

#include <stdint.h>
#include <libtock/tock.h>
#include "hash.h"

bool libtock_hmac_exists(void);

// Function signature for hash callback.
//
// - `arg1` (`returncode_t`): Status from computing the hash.
typedef void (*libtock_hmac_callback_done)(returncode_t);

// Compute a hash over `input_buffer` and store the hash in `hash_buffer`.
returncode_t libtocksync_hmac_compute(libtock_hash_algorithm_t hmac_algorithm,
                                     uint8_t* key_buffer, uint32_t key_length,
                                     uint8_t* input_buffer, uint32_t input_length,
                                     uint8_t* output_buffer, uint32_t output_length);

returncode_t libtock_hmac_compute(libtock_hash_algorithm_t hmac_algorithm,
                                     uint8_t* key_buffer, uint32_t key_length,
                                     uint8_t* input_buffer, uint32_t input_length,
                                     uint8_t* output_buffer, uint32_t output_length,
                                     libtock_hmac_callback_done cb);
