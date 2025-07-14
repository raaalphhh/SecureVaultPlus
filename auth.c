#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"
#include "recovery.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "aes.h"
#include "config.h"

unsigned char aesKey[16]; // Global AES key (128-bit)

#define MAX_PASS_LEN 50
#define MASTER_FILE "master.dat"
#define RESET_NOTE_FILE "reset_note_shown.flag"

int hash(char *password) {
    int sum = 0;
    for (int i = 0; password[i] != '\0'; i++) {
        sum += password[i] * (i + 1);
    }
    return sum;
}

int isMasterPasswordSet() {
    FILE *fp = fopen(MASTER_FILE, "r");
    if (fp) {
        fclose(fp);
        return 1;
    }
    return 0;
}

void maybeShowResetNote() {
    FILE *fp = fopen(RESET_NOTE_FILE, "r");
    if (fp) {
        fclose(fp);
        return;
    }

    printf("[NOTE] Type 'pass reset' during login to trigger recovery. (This message only shows once)\n");

    fp = fopen(RESET_NOTE_FILE, "w");
    if (fp) fclose(fp);
}

void setMasterPassword() {
    if (isMasterPasswordSet()) {
        printf("[!] Master password already set. Cannot overwrite.\n");
        return;
    }

    char pass[MAX_PASS_LEN];
    FILE *fp = fopen(MASTER_FILE, "w");
    if (!fp) {
        printf("[!] Error creating master password file.\n");
        return;
    }

    printf("Enter new master password: ");
    readPassword(pass, MAX_LEN);
    pass[strcspn(pass, "\n")] = 0;

    int hashed = hash(pass);
    fprintf(fp, "%d", hashed);
    fclose(fp);
    clearString(pass, MAX_PASS_LEN);

    printf("[+] Master password set successfully.\n");
    maybeShowResetNote();
    setupRecovery();
}

int isPassResetCommand(const char *input) {
    char cmd[MAX_PASS_LEN];
    strncpy(cmd, input, MAX_PASS_LEN);
    cmd[MAX_PASS_LEN - 1] = '\0';
    toUpperStr(cmd);
    return strcmp(cmd, "PASS RESET") == 0;
}

int login() {
    if (!isMasterPasswordSet()) {
        printf("[!] Master password not set. Please set it first.\n");
        return 0;
    }

    char input[MAX_PASS_LEN];
    int storedHash, inputHash;

    FILE *fp = fopen(MASTER_FILE, "r");
    if (!fp) {
        printf("[!] Error reading master password.\n");
        return 0;
    }

    fscanf(fp, "%d", &storedHash);
    fclose(fp);

    printf("Enter master password: ");
    readPassword(input, MAX_LEN);
    input[strcspn(input, "\n")] = 0;

    if (isPassResetCommand(input)) {
        startRecovery();
        return 0;
    }

    inputHash = hash(input);

    if (inputHash == storedHash) {
        deriveKeyFromPassword(input, aesKey);
        clearString(input, MAX_PASS_LEN);
        printf("[+] Access granted.\n");
        return 1;
    } else {
        clearString(input, MAX_PASS_LEN);
        printf("[!] Incorrect password.\n");
        return 0;
    }
}
