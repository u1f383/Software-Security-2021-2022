#ifndef _CRYPTO_H_
#define _CRYPTO_H_
#define AES_KEY_LENGTH 16
    
#include <openssl/aes.h>
#include <stdint.h>

void mycrypto_try_init();
int hexdump(unsigned char *data, uint16_t len);
int my_encrypt(unsigned char *plaintext, uint16_t *len);
int my_decrypt(unsigned char *cipher, uint16_t *len);

#endif