#include <libtock/tock.h>
#include <stdint.h>
#include "hash_syscalls.h"

#define HASH_INPUT_BUF 0
#define HASH_OUTPUT_BUF 0

#define HASH_COMPUTE 1

#define HASH_DONE 0

bool libtock_hash_driver_exists(void) {
  return driver_exists(HASH_DRIVER_NUMBER);
}

returncode_t libtock_hash_set_done_upcall(subscribe_upcall callback, void* opaque) {
  subscribe_return_t sval = subscribe(HASH_DRIVER_NUMBER, HASH_DONE, callback, opaque);
  return tock_subscribe_return_to_returncode(sval);
}

returncode_t libtock_hash_set_readonly_allow_input_buffer(uint8_t* buffer, uint32_t len) {
  allow_ro_return_t aval = allow_readonly(HASH_DRIVER_NUMBER, HASH_INPUT_BUF, (void*) buffer, len);
  return tock_allow_ro_return_to_returncode(aval);
}

returncode_t libtock_hash_set_readwrite_allow_output_buffer(uint8_t* buffer, uint32_t len) {
  allow_rw_return_t aval = allow_readwrite(HASH_DRIVER_NUMBER, HASH_OUTPUT_BUF, (void*) buffer, len);
  return tock_allow_rw_return_to_returncode(aval);
}

returncode_t libtock_hash_command_start(uint8_t algo) {
  syscall_return_t cval = command(HASH_DRIVER_NUMBER, HASH_COMPUTE, algo, 0);
  return tock_command_return_novalue_to_returncode(cval);
}

returncode_t libtocksync_hash_yield_wait_for_done(void) {
  yield_waitfor_return_t ret;
  ret = yield_wait_for(HASH_DRIVER_NUMBER, HASH_DONE);

  return tock_status_to_returncode(ret.data0);
}
