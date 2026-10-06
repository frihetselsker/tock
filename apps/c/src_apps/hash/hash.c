#include <libtock/tock.h>
#include <stdint.h>
#include "hash.h"
#include "hash_syscalls.h"

static void hash_upcall(int status,
                       __attribute__ ((unused)) int unused1,
                       __attribute__ ((unused)) int unused2, void* opaque) {
  libtock_hash_callback_done cb = (libtock_hash_callback_done) opaque;
  cb(tock_status_to_returncode(status));
}

bool libtock_hash_exists(void) {
  return libtock_hash_driver_exists();
}

returncode_t libtocksync_hash_compute(libtock_hash_algorithm_t hash_algorithm,
                                     uint8_t* input_buffer, uint32_t input_length,
                                     uint8_t* output_buffer, uint32_t output_length) {

  returncode_t ret;

  ret = libtock_hash_set_readonly_allow_input_buffer(input_buffer, input_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hash_set_readwrite_allow_output_buffer(output_buffer, output_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hash_command_start(hash_algorithm);

  if (ret == RETURNCODE_SUCCESS) {
      ret = libtocksync_hash_yield_wait_for_done();
  }

  return ret;
}

returncode_t libtock_hash_compute(libtock_hash_algorithm_t hash_algorithm,
                                    uint8_t *input_buffer, uint32_t input_length,
                                    uint8_t *output_buffer, uint32_t output_length,
                                    libtock_hash_callback_done cb) {
    returncode_t ret;

    ret = libtock_hash_set_readonly_allow_input_buffer(input_buffer, input_length);
    if (ret != RETURNCODE_SUCCESS) return ret;

    ret = libtock_hash_set_readwrite_allow_output_buffer(output_buffer, output_length);
    if (ret != RETURNCODE_SUCCESS) return ret;

    ret = libtock_hash_command_start(hash_algorithm);

    if (ret != RETURNCODE_SUCCESS) return ret;

    ret = libtock_hash_set_done_upcall(hash_upcall, cb);

    return ret;
}
