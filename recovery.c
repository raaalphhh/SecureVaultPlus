#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "config.h"
#include "aes.h"   // for aesEncrypt, aesDecrypt, deriveRecoveryKey, generateRandomIV
#include "utils.h" // for generateRandomBytes (we'll move it here)

#define MASTER_FILE "master.dat"
#define SECQ_FILE "security.dat"
#define MAX_LEN 100

// Generate a numeric OTP of given length
void generateOTP(char *otp, int length)
{
    srand((unsigned int)time(NULL));
    for (int i = 0; i < length - 1; i++)
    {
        otp[i] = '0' + rand() % 10;
    }
    otp[length - 1] = '\0';
}

void hashAnswer(const char *answer, unsigned char *output)
{
    SHA256((const unsigned char *)answer, strlen(answer), output);
}

// Set up the security question/answer
void setupSecurity()
{
    char question[MAX_LEN], answer[MAX_LEN];
    FILE *fp = fopen(SECQ_FILE, "w");

    if (!fp)
    {
        printf("Failed to set up security question.\n");
        return;
    }

    printf("\nSet your security question (e.g. 'Your favorite color?'): ");
    fgets(question, MAX_LEN, stdin);
    question[strcspn(question, "\n")] = 0;

    printf("Set your answer: ");
    fgets(answer, MAX_LEN, stdin);
    answer[strcspn(answer, "\n")] = 0;

    unsigned char salt[SALT_LEN];
    generateRandomBytes(salt, SALT_LEN);
    saveRecoverySalt(salt);

    unsigned char iv[16], key[16], ciphertext[128];
    generateRandomIV(iv);
    deriveRecoveryKey(answer, salt, key);

    int len = aesEncrypt((unsigned char *)answer, strlen(answer), key, iv, ciphertext);

    // Save question + encrypted answer
    fprintf(fp, "%s\n", question);
    fwrite(iv, 1, 16, fp);
    fwrite(&len, sizeof(int), 1, fp); // <--- Add this
    fwrite(ciphertext, 1, len, fp);   // <--- Now we know how much to read

    // Hash the answer using SHA-256 and write it as hex string
    unsigned char hashed[SHA256_DIGEST_LENGTH];
    hashAnswer(answer, hashed);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        fprintf(fp, "%02x", hashed[i]);
    }
    fprintf(fp, "\n");

    fclose(fp);
    clearString(answer, MAX_LEN);

    printf("Security question set successfully.\n");
}

// Ask and verify the user's stored answer
int verifySecurityAnswer()
{
    char question[MAX_LEN], input[MAX_LEN];
    unsigned char salt[SALT_LEN], key[16], iv[16], ciphertext[128], decrypted[128];
    FILE *fp = fopen(SECQ_FILE, "rb");

    if (!fp)
    {
        printf("[!] Security question not set.\n");
        return 0;
    }

    // Step 1: Read question
    fgets(question, MAX_LEN, fp);
    question[strcspn(question, "\n")] = 0;

    fread(iv, 1, AES_IV_SIZE, fp);
    int cipherLen;
    fread(&cipherLen, sizeof(int), 1, fp); // Read the exact ciphertext length
    fread(ciphertext, 1, cipherLen, fp);   // Only read that many bytes

    fclose(fp);

    // Step 4: Ask user for input
    printf("Security Question: %s\nAnswer: ", question);
    fgets(input, MAX_LEN, stdin);
    input[strcspn(input, "\n")] = 0;

    // Step 5: Derive key from input
    loadRecoverySalt(salt);
    deriveRecoveryKey(input, salt, key);

    // Step 6: Decrypt
    int len = aesDecrypt(ciphertext, cipherLen, key, iv, decrypted);
    if (len < 0 || len > sizeof(decrypted))
    {
        printf("[!] Decryption failed.\n");
        return 0;
    }
    decrypted[len] = '\0';

    // Step 7: Compare
    return strcmp(input, (char *)decrypted) == 0;
}

// Simulated OTP check
int simulateOTPCheck()
{
    char otp[7], input[10];
    generateOTP(otp, 7);

    printf("\n[Simulated] OTP sent to your email. (OTP: %s)\n", otp);
    printf("Enter the OTP: ");
    fgets(input, 10, stdin);
    input[strcspn(input, "\n")] = 0;

    return strcmp(input, otp) == 0;
}

// Reset the master password
void resetMasterPassword()
{
    printf("\n--- Master Password Reset ---\n");

    FILE *fp = fopen(MASTER_FILE, "w");
    if (!fp)
    {
        printf("[!] Failed to update master password.\n");
        return;
    }

    char newPass[MAX_LEN];
    printf("Enter new master password: ");
    readPassword(newPass, MAX_LEN);
    newPass[strcspn(newPass, "\n")] = 0;

    int hashed = 0;
    for (int i = 0; newPass[i] != '\0'; i++)
    {
        hashed += newPass[i] * (i + 1);
    }

    fprintf(fp, "%d", hashed);
    fclose(fp);

    clearString(newPass, MAX_LEN);
    printf("[+] Master password has been reset.\n");
}

// Run during setup
void setupRecovery()
{
    setupSecurity();
    // simulateEmailSetup(); // Future feature
}

// Triggered if user types 'pass reset'
void startRecovery()
{
    printf("\n[Recovery Mode Initiated]\n");

    if (verifySecurityAnswer())
    {
        printf("[OK] Security answer verified.\n");
        resetMasterPassword();
        return;
    }

    printf("[!] Incorrect answer. Trying OTP fallback...\n");

    if (simulateOTPCheck())
    {
        printf("[OK] OTP verified.\n");
        resetMasterPassword();
    }
    else
    {
        printf("[X] Recovery failed. Access denied.\n");
    }
}
