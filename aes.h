#ifndef AES_H
#define AES_H

#include <stdint.h>
#include "config.h"

#define AES_KEY_SIZE 16
#define AES_IV_SIZE 16

extern unsigned char AES_KEY[AES_KEY_SIZE];

void deriveKeyFromPassword(const char *password, unsigned char *key_out);

void deriveRecoveryKey(const char *password, const unsigned char *salt, unsigned char *keyOut);

void generateRandomIV(unsigned char *iv);

int aesEncrypt(const unsigned char *plaintext, int plaintext_len,
               const unsigned char *key, const unsigned char *iv,
               unsigned char *ciphertext);

int aesDecrypt(const unsigned char *ciphertext, int ciphertext_len,
               const unsigned char *key, const unsigned char *iv,
               unsigned char *plaintext);

int loadSaltFromFile(unsigned char *salt, size_t len);

void saveSaltToFile(const unsigned char *salt, size_t len);

#endif
