// vault_struct.h
#ifndef VAULT_STRUCT_H
#define VAULT_STRUCT_H
#include "config.h"

#pragma pack(push, 1)
typedef struct {
    char site[50];
    char username[50];
    unsigned char iv[16];            // AES IV
    unsigned char password[128];     // Encrypted password
    int password_len;
} Credential;
#pragma pack(pop)

#endif