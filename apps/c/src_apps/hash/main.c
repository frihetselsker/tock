#include <stdint.h>
#include <stdio.h>

#include <libtock/tock.h>
#include <libtock/interface/console.h>
#include "hash.h"
#include "hmac.h"
#include "hkdf.h"

int main(void) {
    if (libtock_hash_exists()) {
        printf("------------Hash Test---------------\n");

        uint8_t input_buffer[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0x98, 0x76, 0x54, 0x32, 0x12, 0x34, 0x56, 0x78, 0x90, 0x98, 0x76, 0x54, 0x32, 0x12};
        uint8_t output_buffer[32];
        uint8_t correct_output_buffer[] = {0x0a, 0x68, 0xe0, 0xa0, 0x19, 0xe2, 0x38, 0xb0, 0x21, 0xaf, 0x8b, 0xbc, 0x67, 0x36, 0x42, 0xe1, 0xf8, 0x88, 0x93, 0xf4, 0xf7, 0xb6, 0x56, 0xcf, 0xa2, 0xaa, 0x25, 0x53, 0x6c, 0xc8, 0x94, 0xb3};
        returncode_t ret;
        ret = libtocksync_hash_compute(SHA256, input_buffer, sizeof(input_buffer) / sizeof(uint8_t), output_buffer, sizeof(output_buffer) / sizeof(uint8_t));
        if (ret == RETURNCODE_SUCCESS) {
            printf("[HASH] Received the output buffer\n");
            for (int i = 0; i < sizeof(correct_output_buffer) / sizeof(uint8_t); i++) {
                printf("%02x", correct_output_buffer[i]);
            }
            printf("\n");
            bool match = true;
            printf("[HASH] Got: ");
            for (int i = 0; i < sizeof(output_buffer) / sizeof(uint8_t); i++) {
                if (correct_output_buffer[i] != output_buffer[i]) {
                  match = false;
                }
                printf("%02x", output_buffer[i]);
            }
            printf("\n");

            if (match) {
                printf("[HASH] Hash computation correct.\n");
            } else {
                printf("ERROR! Hash computation incorrect.\n");
            }
        } else {
            printf("[HASH] Failed to compute simple hash\n");
        }
    } else {
        printf("[HASH] No driver found\n");
        return -1;
    }
    // Hash Check

   // HMAC Check
   if (libtock_hmac_exists()) {
           printf("------------HMAC Test---------------\n");

           uint8_t input_buffer[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0x98, 0x76, 0x54, 0x32, 0x12, 0x34, 0x56, 0x78, 0x90, 0x98, 0x76, 0x54, 0x32, 0x12};
           uint8_t key_buffer[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0x98, 0x76, 0x54, 0x32, 0x12, 0x34, 0x56, 0x78, 0x90, 0x98, 0x76, 0x54, 0x32, 0x12};
           uint8_t output_buffer[32];
           uint8_t correct_output_buffer[] = {0xf5, 0xb9, 0x1b, 0xe6, 0x38, 0x15, 0x65, 0x61, 0xbd, 0x2e, 0x21, 0xcc, 0xab, 0x7d, 0x6e, 0xb2, 0x3f, 0xc4, 0x0f, 0xf2, 0x1f, 0x24, 0xab, 0x28, 0xc1, 0x42, 0xc9, 0xcf, 0xbe, 0x94, 0x8b, 0x17};
           returncode_t ret;
           ret = libtocksync_hmac_compute(SHA256, key_buffer, sizeof(key_buffer) / sizeof(uint8_t), input_buffer, sizeof(input_buffer) / sizeof(uint8_t), output_buffer, sizeof(output_buffer) / sizeof(uint8_t));
           if (ret == RETURNCODE_SUCCESS) {
               printf("[HMAC] Received the output buffer\n");
               for (int i = 0; i < sizeof(correct_output_buffer) / sizeof(uint8_t); i++) {
                   printf("%02x", correct_output_buffer[i]);
               }
               printf("\n");
               bool match = true;
               printf("[HMAC] Got: ");
               for (int i = 0; i < sizeof(output_buffer) / sizeof(uint8_t); i++) {
                   if (correct_output_buffer[i] != output_buffer[i]) {
                     match = false;
                   }
                   printf("%02x", output_buffer[i]);
               }
               printf("\n");

               if (match) {
                   printf("[HMAC] Hash computation correct.\n");
               } else {
                   printf("[HMAC] ERROR! Hash computation incorrect.\n");
               }
           } else {
               printf("[HMAC] Failed to compute simple hash\n");
           }
       } else {
           printf("[HMAC] No driver found\n");
           return -1;
       }
   // HKDF Check
   if (libtock_hkdf_exists()) {
           printf("------------HKDF Test---------------\n");

           uint8_t ikm_buffer[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
           uint8_t salt_buffer[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
           uint8_t info_buffer[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
           uint8_t prk_buffer[32];
           uint8_t okm_buffer[42];
           uint8_t correct_output_hash[] = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
           returncode_t ret;
           ret = libtocksync_hkdf_compute(SHA256, ikm_buffer, sizeof(ikm_buffer) / sizeof(uint8_t),
                                            salt_buffer, sizeof(salt_buffer) / sizeof(uint8_t),
                                            info_buffer, sizeof(info_buffer) / sizeof(uint8_t),
                                            prk_buffer, sizeof(prk_buffer) / sizeof(uint8_t),
                                            okm_buffer, sizeof(okm_buffer) / sizeof(uint8_t));
           if (ret == RETURNCODE_SUCCESS) {
               printf("[HKDF] Received the OKM buffer\n");
               for (int i = 0; i < sizeof(correct_output_hash) / sizeof(uint8_t); i++) {
                   printf("%02x", correct_output_hash[i]);
               }
               printf("\n");
               bool match = true;
               printf("Got: ");
               for (int i = 0; i < sizeof(okm_buffer) / sizeof(uint8_t); i++) {
                   if (correct_output_hash[i] != okm_buffer[i]) {
                     match = false;
                   }
                   printf("%02x", okm_buffer[i]);
               }
               printf("\n");

               if (match) {
                   printf("[HKDF] Hash computation correct.\n");
               } else {
                   printf("[HKDF] ERROR! Hash computation incorrect.\n");
               }
           } else {
               printf("[HKDF] Failed to compute simple hash\n");
           }
       } else {
           printf("[HKDF] No driver found\n");
           return -1;
       }
    return 0;
}
