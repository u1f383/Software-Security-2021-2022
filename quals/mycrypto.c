#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define AES_KEY_LENGTH 32

unsigned char iv[AES_BLOCK_SIZE] = {'t', 'e', 's', 't', 't', 'e', 's', 't', 't', 'e', 's', 't', 't', 'e', 's', 't'};

int my_encrypt(unsigned char *plaintext, unsigned char *key, uint16_t len)
{
    AES_KEY encryption_key;
    unsigned char iv_enc[AES_BLOCK_SIZE];
    unsigned char output[32] = {0};
    memcpy(iv_enc, iv, AES_BLOCK_SIZE);

    AES_set_encrypt_key(key, AES_KEY_LENGTH * 8, &(encryption_key));
    AES_cbc_encrypt(plaintext, output, len, &encryption_key, iv_enc, AES_ENCRYPT);
}

int my_decrypt(unsigned char *cipher, unsigned char *key, uint16_t len)
{
    AES_KEY decryption_key;
    unsigned char iv_dec[AES_BLOCK_SIZE];
    unsigned char output[32] = {0};

    memcpy(iv_dec, iv, AES_BLOCK_SIZE);
    AES_set_decrypt_key(key, AES_KEY_LENGTH * 8, &(decryption_key));
    AES_cbc_encrypt(cipher, output, len, &decryption_key, iv_dec, AES_DECRYPT);
}