#pragma once

#include <stdint.h>
#include <libtock/tock.h>
#include "hash_syscalls.h"

typedef enum {
  MD5 = 0,
  SHA1 = 1,
  SHA224 = 2,
  SHA256 = 3,
  SHA384 = 4,
  SHA512 = 5,
  SHA512_224 = 6,
  SHA512_256 = 7,
} libtock_hash_algorithm_t;

bool libtock_hash_exists(void);

// Function signature for hash callback.
//
// - `arg1` (`returncode_t`): Status from computing the hash.
typedef void (*libtock_hash_callback_done)(returncode_t);

// Compute a hash over `input_buffer` and store the hash in `hash_buffer`.
returncode_t libtocksync_hash_compute(libtock_hash_algorithm_t hash_typ,
                                     uint8_t* input_buffer, uint32_t input_length,
                                     uint8_t* output_buffer, uint32_t output_length);

returncode_t libtock_hash_compute(libtock_hash_algorithm_t hash_type,
                                     uint8_t* input_buffer, uint32_t input_length,
                                     uint8_t* output_buffer, uint32_t output_length,
                                     libtock_hash_callback_done cb);
