
#include <stdint.h>
#include <libtock/tock.h>

#define HKDF_DRIVER_NUMBER 0x40007

bool libtock_hkdf_driver_exists(void);

returncode_t libtock_hkdf_set_done_upcall(subscribe_upcall callback, void* opaque);

returncode_t libtock_hkdf_set_readonly_allow_salt_buffer(uint8_t* buffer, uint32_t len);
returncode_t libtock_hkdf_set_readonly_allow_ikm_buffer(uint8_t* buffer, uint32_t len);
returncode_t libtock_hkdf_set_readonly_allow_info_buffer(uint8_t* buffer, uint32_t len);

returncode_t libtock_hkdf_set_readwrite_allow_prk_buffer(uint8_t* buffer, uint32_t len);
returncode_t libtock_hkdf_set_readwrite_allow_okm_buffer(uint8_t* buffer, uint32_t len);

returncode_t libtock_hkdf_command_start(uint8_t algo);

returncode_t libtocksync_hkdf_yield_wait_for_done(void);
