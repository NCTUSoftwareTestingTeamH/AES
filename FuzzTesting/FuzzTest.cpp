#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include"../type.h"
#include"../AES256.h"

int
main(int argc, char* argv[]) {
    srand(time(nullptr));

    size_t plaintextLen = rand() % 9999;
    size_t passwordLen = rand() % 9999;

    UC* plaintext = (UC*) malloc(sizeof(UC) * (plaintextLen + 1));
    read(0, plaintext, plaintextLen);

    char* password = (char*) malloc(sizeof(char) * (passwordLen + 1));
    read(0, password, passwordLen);

    AES256 cipher(password, passwordLen);
    cipher.Encrypte(plaintext, plaintextLen);
    cipher.Decrypte(plaintext, plaintextLen);

    return 0;
}
