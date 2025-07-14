#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"
#include "config.h"
#define SALT_FILE "salt.dat"


extern unsigned char aesKey[16];  // AES key derived from master password

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int aesEncrypt(const unsigned char *plaintext, int plaintext_len,
               const unsigned char *key, const unsigned char *iv,
               unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aesDecrypt(const unsigned char *ciphertext, int ciphertext_len,
               const unsigned char *key, const unsigned char *iv,
               unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void deriveKeyFromPassword(const char *password, unsigned char *key_out) {
    unsigned char salt[16];
    const int iterations = 100000;

    if (!loadSaltFromFile(salt, sizeof(salt))) {
        generateRandomIV(salt); // reuse IV function to generate salt
        saveSaltToFile(salt, sizeof(salt));
    }

    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                           iterations, EVP_sha256(), sizeof(aesKey), aesKey)) {
        printf("Key derivation failed.\n");
        exit(1);
    }
}

void generateRandomIV(unsigned char *iv_out) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        fread(iv_out, 1, AES_IV_SIZE, fp);
        fclose(fp);
    } else {
        for (int i = 0; i < AES_IV_SIZE; i++)
            iv_out[i] = rand() % 256;
    }
}

int loadSaltFromFile(unsigned char *salt, size_t len) {
    FILE *fp = fopen(SALT_FILE, "rb");
    if (!fp) return 0;

    size_t read = fread(salt, 1, len, fp);
    fclose(fp);
    return read == len;
}

void saveSaltToFile(const unsigned char *salt, size_t len) {
    FILE *fp = fopen(SALT_FILE, "wb");
    if (!fp) return;

    fwrite(salt, 1, len, fp);
    fclose(fp);
}

void deriveRecoveryKey(const char *password, const unsigned char *salt, unsigned char *keyOut) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN,
                      100000, EVP_sha256(), 16, keyOut); // AES-128
}