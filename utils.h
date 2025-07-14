// utils.h
#ifndef UTILS_H
#define UTILS_H
#include "config.h"

void clearString(char *str, int len);
void toUpperStr(char *str);
void readPassword(char *buffer, int maxLen);
void saveRecoverySalt(const unsigned char *salt);
int loadRecoverySalt(unsigned char *salt);
void generateRandomBytes(unsigned char *buf, int len);

#endif