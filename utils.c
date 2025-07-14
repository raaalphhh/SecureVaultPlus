// utils.c
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "config.h"
#include <openssl/rand.h>

#define RECOVERY_SALT_FILE "recovery_salt.dat"
#define SALT_LEN 16

void clearString(char *str, int len) {
    for (int i = 0; i < len; i++) {
        str[i] = 0;
    }
}

void toUpperStr(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = toupper(str[i]);
    }
}

void saveRecoverySalt(const unsigned char *salt) {
    FILE *fp = fopen(RECOVERY_SALT_FILE, "wb");
    if (fp) {
        fwrite(salt, 1, SALT_LEN, fp);
        fclose(fp);
    }
}

int loadRecoverySalt(unsigned char *salt) {
    FILE *fp = fopen(RECOVERY_SALT_FILE, "rb");
    if (!fp) return 0;
    fread(salt, 1, SALT_LEN, fp);
    fclose(fp);
    return 1;
}

// ------------------- ADD THIS -------------------

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void readPassword(char *buffer, int maxLen) {
    int i = 0;
    char ch;

#ifdef _WIN32
    while (i < maxLen - 1) {
        ch = _getch();
        if (ch == '\r') break;
        if (ch == '\b' && i > 0) {
            i--;
            printf("\b \b");
        } else if (isprint(ch)) {
            buffer[i++] = ch;
            printf("*");
        }
    }
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while (i < maxLen - 1 && (ch = getchar()) != '\n') {
        if (ch == 127 || ch == '\b') {
            if (i > 0) {
                i--;
                printf("\b \b");
            }
        } else if (isprint(ch)) {
            buffer[i++] = ch;
            printf("*");
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    buffer[i] = '\0';
    buffer[strcspn(buffer, "\n")] = 0;  // Just extra safety
    printf("\n");
}

void generateRandomBytes(unsigned char *buf, int len) {
    RAND_bytes(buf, len);
}