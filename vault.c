// vault.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vault.h"
#include "utils.h"
#include "aes.h"
#include "vault_struct.h"
#include <openssl/evp.h>
#include "config.h"

#define VAULT_FILE "vault.dat"
#define BACKUP_FILE "vault.bak"

extern unsigned char aesKey[16];

void addCredential()
{
    Credential c;
    FILE *fp = fopen(VAULT_FILE, "ab");
    if (!fp)
    {
        printf("[ERROR] Could not open vault.\n");
        return;
    }

    printf("Enter site/app name: ");
    fgets(c.site, sizeof(c.site), stdin);
    c.site[strcspn(c.site, "\n")] = 0;

    printf("Enter username: ");
    fgets(c.username, sizeof(c.username), stdin);
    c.username[strcspn(c.username, "\n")] = 0;

    char plainPass[100];
    printf("Enter password: ");
    fgets(plainPass, sizeof(plainPass), stdin);
    plainPass[strcspn(plainPass, "\n")] = 0;

    generateRandomIV(c.iv);
    c.password_len = aesEncrypt((unsigned char *)plainPass, strlen(plainPass),
                                aesKey, c.iv, c.password);

    clearString(plainPass, sizeof(plainPass));

    fwrite(&c, sizeof(Credential), 1, fp);
    fclose(fp);
    printf("[INFO] Credential saved securely.\n");
}

void viewCredentials()
{
    Credential c;
    FILE *fp = fopen(VAULT_FILE, "rb");
    if (!fp)
    {
        printf("[INFO] No credentials stored.\n");
        return;
    }

    printf("\n");
    printf("             S   T   O   R   E   D  \n");
    printf("\n");
    printf("   C   R   E   D   E   N   T   I   A   L   S  \n");
    printf("\n");

    while (fread(&c, sizeof(Credential), 1, fp))
    {
        unsigned char decrypted[256];
        int len = aesDecrypt(c.password, c.password_len, aesKey, c.iv, decrypted);

        if (len < 0 || len > sizeof(decrypted))
        {
            printf("[WARNING] Decryption failed for site: %s. Skipping.\n", c.site);
            continue;
        }

        decrypted[len] = '\0';
        printf("Site: %s\nUsername: %s\nPassword: %s\n\n", c.site, c.username, decrypted);
        clearString((char *)decrypted, sizeof(decrypted));
    }
    fclose(fp);
}

void exportVault()
{
    FILE *src = fopen(VAULT_FILE, "rb");
    FILE *dst = fopen(BACKUP_FILE, "wb");
    if (!src || !dst)
    {
        printf("[ERROR] Export failed.\n");
        if (src)
            fclose(src);
        if (dst)
            fclose(dst);
        return;
    }

    char buffer[1024];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
        fwrite(buffer, 1, bytes, dst);

    fclose(src);
    fclose(dst);
    printf("[INFO] Vault exported to '%s'.\n", BACKUP_FILE);
}

void importVault()
{
    FILE *src = fopen(BACKUP_FILE, "rb");
    FILE *dst = fopen(VAULT_FILE, "wb");
    if (!src || !dst)
    {
        printf("[ERROR] Import failed.\n");
        if (src)
            fclose(src);
        if (dst)
            fclose(dst);
        return;
    }

    char buffer[1024];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
        fwrite(buffer, 1, bytes, dst);

    fclose(src);
    fclose(dst);
    printf("[INFO] Vault imported from '%s'.\n", BACKUP_FILE);
}