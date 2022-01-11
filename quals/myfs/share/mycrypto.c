#include "mycrypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

unsigned char iv[AES_BLOCK_SIZE] = {0};
unsigned char mycrypto_is_init = 0;

void mycrypto_try_init()
{
    if (mycrypto_is_init)
        return;
    
    RAND_bytes(iv, AES_BLOCK_SIZE);
    mycrypto_is_init = 1;
}

void hexdump(unsigned char *data, uint16_t len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
}

int my_encrypt(unsigned char *plaintext, unsigned char *key, uint16_t *len)
{
    if (strlen(key) != AES_KEY_LENGTH)
        return -1;

    mycrypto_try_init();

    AES_KEY encryption_key;
    unsigned char iv_enc[AES_BLOCK_SIZE];
    memcpy(iv_enc, iv, AES_BLOCK_SIZE);

    // padding
    if (*len % 0x10) {
        memset(plaintext + *len, 0x10 - (*len % 0x10), 0x10 - (*len % 0x10));
        *len += 0x10 - (*len % 0x10);
    }

    unsigned char *output = (unsigned char *) malloc(*len);

    AES_set_encrypt_key(key, AES_KEY_LENGTH * 8, &(encryption_key));
    AES_cbc_encrypt(plaintext, output, *len, &encryption_key, iv_enc, AES_ENCRYPT);

    memcpy(plaintext, output, *len);
    free(output);
    return 0;
}

int my_decrypt(unsigned char *cipher, unsigned char *key, uint16_t *len)
{
    if (strlen(key) != AES_KEY_LENGTH)
        return -1;
    
    if (*len % 0x10)
        return -1;

    mycrypto_try_init();

    AES_KEY decryption_key;
    unsigned char iv_dec[AES_BLOCK_SIZE];
    unsigned char *output = (unsigned char *) malloc(*len);

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    AES_set_decrypt_key(key, AES_KEY_LENGTH * 8, &(decryption_key));
    AES_cbc_encrypt(cipher, output, *len, &decryption_key, iv_dec, AES_DECRYPT);

    // check padding
    unsigned char last = output[*len - 1];
    int cnt = 0;
    if (last >= 0 && last < 0x10) {
        for (int i = *len - 1; output[i] == last; i--)
            cnt++;
        if (cnt != last) {
            free(output);
            return -1;
        }
        memset(cipher, 0, *len);
        *len -= last;
    }
    memcpy(cipher, output, *len);
    free(output);
    
    return 0;
}