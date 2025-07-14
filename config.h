// config.h

#ifndef CONFIG_H
#define CONFIG_H

#define MAX_LEN 100         // Used for passwords, usernames, etc.
#define SALT_LEN 16         // 128-bit salt for PBKDF2
#define KEY_LEN 16          // AES-128 key = 16 bytes
#define IV_LEN 16           // AES block size = 16 bytes

#define MASTER_FILE "master.dat"
#define SALT_FILE "salt.dat"
#define VAULT_FILE "vault.dat"
#define SECQ_FILE "security.dat"
#define RECOVERY_SALT_FILE "recovery_salt.dat"

#endif
