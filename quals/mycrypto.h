#ifndef _CRYPTO_H_
#define _CRYPTO_H_
    
#include <openssl/aes.h>
#include <stdint.h>

#define AES_KEY_LENGTH 32

int my_encrypt(unsigned char *plaintext, unsigned char *key, uint16_t len);
int my_decrypt(unsigned char *cipher, unsigned char *key, uint16_t len);

#endif