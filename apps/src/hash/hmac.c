#include <libtock/tock.h>
#include <stdint.h>
#include "hash.h"
#include "hmac.h"
#include "hmac_syscalls.h"


static void hmac_upcall(int status,
                       __attribute__ ((unused)) int unused1,
                       __attribute__ ((unused)) int unused2, void* opaque) {
  libtock_hmac_callback_done cb = (libtock_hmac_callback_done) opaque;
  cb(tock_status_to_returncode(status));
}

bool libtock_hmac_exists(void) {
  return libtock_hmac_driver_exists();
}

returncode_t libtocksync_hmac_compute(libtock_hash_algorithm_t hmac_algorithm,
                                        uint8_t *key_buffer, uint32_t key_length,
                                        uint8_t *input_buffer, uint32_t input_length,
                                        uint8_t *output_buffer, uint32_t output_length) {

  returncode_t ret;

  ret = libtock_hmac_set_readonly_allow_input_buffer(input_buffer, input_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hmac_set_readonly_allow_key_buffer(key_buffer, key_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hmac_set_readwrite_allow_output_buffer(output_buffer, output_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hmac_command_start(hmac_algorithm);

  if (ret == RETURNCODE_SUCCESS) {
      ret = libtocksync_hmac_yield_wait_for_done();
  }

  return ret;
}


returncode_t libtock_hmac_compute(libtock_hash_algorithm_t hmac_algorithm,
                                        uint8_t *key_buffer, uint32_t key_length,
                                        uint8_t *input_buffer, uint32_t input_length,
                                        uint8_t *output_buffer, uint32_t output_length,
                                        libtock_hmac_callback_done cb) {

  returncode_t ret;

  ret = libtock_hmac_set_readonly_allow_input_buffer(input_buffer, input_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hmac_set_readonly_allow_key_buffer(key_buffer, key_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hmac_set_readwrite_allow_output_buffer(output_buffer, output_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hmac_command_start(hmac_algorithm);

  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hmac_set_done_upcall(hmac_upcall, cb);

  return ret;
}
