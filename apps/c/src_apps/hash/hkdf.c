#include <libtock/tock.h>
#include <stdint.h>
#include "hash.h"
#include "hkdf.h"
#include "hkdf_syscalls.h"


static void hkdf_upcall(int status,
                       __attribute__ ((unused)) int unused1,
                       __attribute__ ((unused)) int unused2, void* opaque) {
  libtock_hkdf_callback_done cb = (libtock_hkdf_callback_done) opaque;
  cb(tock_status_to_returncode(status));
}

bool libtock_hkdf_exists(void) {
  return libtock_hkdf_driver_exists();
}

returncode_t libtocksync_hkdf_compute(libtock_hash_algorithm_t hkdf_algorithm,
                                        uint8_t* ikm_buffer, uint32_t ikm_length,
                                        uint8_t* salt_buffer, uint32_t salt_length,
                                        uint8_t* info_buffer, uint32_t info_length,
                                        uint8_t* prk_buffer, uint32_t prk_length,
                                        uint8_t* okm_buffer, uint32_t okm_length) {

  returncode_t ret;

  ret = libtock_hkdf_set_readonly_allow_ikm_buffer(ikm_buffer, ikm_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  if (salt_buffer != NULL) {
     ret = libtock_hkdf_set_readonly_allow_salt_buffer(salt_buffer, salt_length);
     if (ret != RETURNCODE_SUCCESS) return ret;
  }

  if (info_buffer != NULL) {
     ret = libtock_hkdf_set_readonly_allow_info_buffer(info_buffer, info_length);
     if (ret != RETURNCODE_SUCCESS) return ret;
  }

  ret = libtock_hkdf_set_readwrite_allow_prk_buffer(prk_buffer, prk_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hkdf_set_readwrite_allow_okm_buffer(okm_buffer, okm_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hkdf_command_start(hkdf_algorithm);

  if (ret == RETURNCODE_SUCCESS) {
      ret = libtocksync_hkdf_yield_wait_for_done();
  }

  return ret;
}

returncode_t libtock_hkdf_compute(libtock_hash_algorithm_t hkdf_algorithm,
                                        uint8_t* ikm_buffer, uint32_t ikm_length,
                                        uint8_t* salt_buffer, uint32_t salt_length,
                                        uint8_t* info_buffer, uint32_t info_length,
                                        uint8_t* prk_buffer, uint32_t prk_length,
                                        uint8_t* okm_buffer, uint32_t okm_length,
                                        libtock_hkdf_callback_done cb) {

  returncode_t ret;

  ret = libtock_hkdf_set_readonly_allow_ikm_buffer(ikm_buffer, ikm_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  if (salt_buffer != NULL) {
     ret = libtock_hkdf_set_readonly_allow_salt_buffer(salt_buffer, salt_length);
     if (ret != RETURNCODE_SUCCESS) return ret;
  }

  if (info_buffer != NULL) {
     ret = libtock_hkdf_set_readonly_allow_info_buffer(info_buffer, info_length);
     if (ret != RETURNCODE_SUCCESS) return ret;
  }

  ret = libtock_hkdf_set_readwrite_allow_prk_buffer(prk_buffer, prk_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hkdf_set_readwrite_allow_okm_buffer(okm_buffer, okm_length);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hkdf_command_start(hkdf_algorithm);
  if (ret != RETURNCODE_SUCCESS) return ret;

  ret = libtock_hkdf_set_done_upcall(hkdf_upcall, cb);

  return ret;
}
