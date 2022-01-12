#include "mycrypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

unsigned char key[AES_KEY_LENGTH + 1] = {0};
unsigned char mycrypto_is_init = 0;

void mycrypto_try_init()
{
    if (mycrypto_is_init)
        return;
    
    do {
        RAND_bytes(key, AES_KEY_LENGTH);
    } while (strlen(key) != 16);

    mycrypto_is_init = 1;
}

int hexdump(unsigned char *data, uint16_t len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    return 0;
}

int my_encrypt(unsigned char *plaintext, uint16_t *len)
{
    mycrypto_try_init();

    AES_KEY encryption_key;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char backup_iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    memcpy(backup_iv, iv, AES_BLOCK_SIZE);

    if (*len % 0x10) {
        memset(plaintext + *len, 0x10 - (*len % 0x10), 0x10 - (*len % 0x10));
        *len += (0x10 - (*len % 0x10)) + AES_BLOCK_SIZE;
    } else {
        *len += AES_BLOCK_SIZE;
    }

    unsigned char *output = (unsigned char *) malloc(*len);

    AES_set_encrypt_key(key, AES_KEY_LENGTH * 8, &(encryption_key));
    AES_cbc_encrypt(plaintext, output,
                    *len - AES_BLOCK_SIZE, &encryption_key, iv, AES_ENCRYPT);

    memcpy(plaintext, backup_iv, AES_BLOCK_SIZE);
    memcpy(plaintext + AES_BLOCK_SIZE, output, *len - AES_BLOCK_SIZE);
    free(output);
    return 0;
}

int my_decrypt(unsigned char *cipher, uint16_t *len)
{
    mycrypto_try_init();
    
    if (*len % AES_BLOCK_SIZE)
        return -1;

    AES_KEY decryption_key;
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, cipher, AES_BLOCK_SIZE);

    unsigned char *output = (unsigned char *) malloc(*len);

    AES_set_decrypt_key(key, AES_KEY_LENGTH * 8, &(decryption_key));
    AES_cbc_encrypt(cipher + AES_BLOCK_SIZE, output,
                    *len - AES_BLOCK_SIZE, &decryption_key, iv, AES_DECRYPT);

    int cnt = 0;
    int i = *len - AES_BLOCK_SIZE - 1;
    unsigned char last = output[i];

    if (last >= 0x10)
        return -1;

    for (; output[i] == last; i--)
        cnt++;

    if (cnt != last) {
        free(output);
        return -1;
    }

    memset(cipher, 0, *len);
    *len -= last + AES_BLOCK_SIZE;
    memcpy(cipher, output, *len);
    free(output);
    
    return 0;
}