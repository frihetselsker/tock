
#include <libtock/tock.h>
#include <stdint.h>
#include "hkdf_syscalls.h"

#define HKDF_SALT_BUF 0
#define HKDF_IKM_BUF 1
#define HKDF_INFO_BUF 2

#define HKDF_PRK_BUF 0
#define HKDF_OKM_BUF 1

#define HKDF_COMPUTE 1

#define HKDF_DONE 0

bool libtock_hkdf_driver_exists(void) {
  return driver_exists(HKDF_DRIVER_NUMBER);
}

returncode_t libtock_hkdf_set_done_upcall(subscribe_upcall callback, void* opaque) {
  subscribe_return_t sval = subscribe(HKDF_DRIVER_NUMBER, HKDF_DONE, callback, opaque);
  return tock_subscribe_return_to_returncode(sval);
}

returncode_t libtock_hkdf_set_readonly_allow_ikm_buffer(uint8_t *buffer, uint32_t len) {
    allow_ro_return_t aval = allow_readonly(HKDF_DRIVER_NUMBER, HKDF_IKM_BUF, (void*) buffer, len);
    return tock_allow_ro_return_to_returncode(aval);
}

returncode_t libtock_hkdf_set_readonly_allow_salt_buffer(uint8_t *buffer, uint32_t len) {
    allow_ro_return_t aval = allow_readonly(HKDF_DRIVER_NUMBER, HKDF_SALT_BUF, (void*) buffer, len);
    return tock_allow_ro_return_to_returncode(aval);
}

returncode_t libtock_hkdf_set_readonly_allow_info_buffer(uint8_t *buffer, uint32_t len) {
    allow_ro_return_t aval = allow_readonly(HKDF_DRIVER_NUMBER, HKDF_INFO_BUF, (void*) buffer, len);
    return tock_allow_ro_return_to_returncode(aval);
}

returncode_t libtock_hkdf_set_readwrite_allow_prk_buffer(uint8_t* buffer, uint32_t len) {
  allow_rw_return_t aval = allow_readwrite(HKDF_DRIVER_NUMBER, HKDF_PRK_BUF, (void*) buffer, len);
  return tock_allow_rw_return_to_returncode(aval);
}

returncode_t libtock_hkdf_set_readwrite_allow_okm_buffer(uint8_t* buffer, uint32_t len) {
  allow_rw_return_t aval = allow_readwrite(HKDF_DRIVER_NUMBER, HKDF_OKM_BUF, (void*) buffer, len);
  return tock_allow_rw_return_to_returncode(aval);
}

returncode_t libtock_hkdf_command_start(uint8_t algo) {
  syscall_return_t cval = command(HKDF_DRIVER_NUMBER, HKDF_COMPUTE, algo, 0);
  return tock_command_return_novalue_to_returncode(cval);
}

returncode_t libtocksync_hkdf_yield_wait_for_done(void) {
  yield_waitfor_return_t ret;
  ret = yield_wait_for(HKDF_DRIVER_NUMBER, HKDF_DONE);

  return tock_status_to_returncode(ret.data0);
}
