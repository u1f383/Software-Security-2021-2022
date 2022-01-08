#ifndef _CRYPTO_H_
#define _CRYPTO_H_
#define AES_KEY_LENGTH 16
    
#include <openssl/aes.h>
#include <stdint.h>

void mycrypto_try_init();
void hexdump(unsigned char *data, uint16_t len);
int my_encrypt(unsigned char *plaintext, unsigned char *key, uint16_t *len);
int my_decrypt(unsigned char *cipher, unsigned char *key, uint16_t *len);

#endif