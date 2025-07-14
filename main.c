#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auth.h"
#include "vault.h"
#include "config.h"
#include "recovery.h" // Make sure to include this

#define INPUT_LEN 100

void printBanner()
{
    printf("\n");
    printf(" __        __   _                            \n");
    printf(" \\ \\      / /__| | ___ ___  _ __ ___   ___  \n");
    printf("  \\ \\ /\\ / / _ \\ |/ __/ _ \\| '_ ` _ \\ / _ \\ \n");
    printf("   \\ V  V /  __/ | (_| (_) | | | | | |  __/ \n");
    printf("    \\_/\\_/ \\___|_|\\___\\___/|_| |_| |_|\\___|  \n");
    printf("                                             \n");
    printf("                             SecureVault+\n\n");
}

void printMenu()
{
    printf("\n==== SecureVault+ ====\n");
    printf("[1] Set Master Password\n");
    printf("[2] Login\n");
    printf("[3] Exit\n");
    printf(">> Choose an option: ");
}

int main()
{
    char input[INPUT_LEN];
    int loggedIn = 0;

    printBanner();

    while (1)
    {
        printMenu();
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0'; // Remove newline

        if (strcmp(input, "1") == 0)
        {
            setMasterPassword();
        }
        else if (strcmp(input, "2") == 0)
        {
            loggedIn = login();
            if (loggedIn)
            {
                char vaultInput[INPUT_LEN];

                do
                {
                    printf("\n-- Vault Menu --\n");
                    printf("[1] Add Credential\n");
                    printf("[2] View Credentials\n");
                    printf("[3] Export Vault\n");
                    printf("[4] Import Vault\n");
                    printf("[5] Logout\n");
                    printf(">> Choose an option: ");
                    fgets(vaultInput, sizeof(vaultInput), stdin);
                    vaultInput[strcspn(vaultInput, "\n")] = '\0'; // Remove newline

                    if (strcmp(vaultInput, "1") == 0)
                    {
                        addCredential();
                    }
                    else if (strcmp(vaultInput, "2") == 0)
                    {
                        viewCredentials();
                    }
                    else if (strcmp(vaultInput, "3") == 0)
                    {
                        exportVault();
                    }
                    else if (strcmp(vaultInput, "4") == 0)
                    {
                        importVault();
                    }
                    else if (strcmp(vaultInput, "5") == 0)
                    {
                        printf("Logging out...\n");
                        break;
                    }
                    else
                    {
                        printf("Invalid option. Please enter a number between 1–5.\n");
                    }
                } while (1);
            }
        }
        else if (strcmp(input, "3") == 0)
        {
            printf("Exiting SecureVault+...\n");
            return 0;
        }
        else if (strcmp(input, "pass reset") == 0)
        {
            printf("\n[Recovery Mode Initiated]\n");
            startRecovery();
        }
        else
        {
            printf("Invalid input. Try again.\n");
        }
    }

    return 0;
}
