#pragma once
#include <stddef.h>
unsigned char* file_read(const char* path, long* size);
void SHA_256(const unsigned char* data, size_t size, unsigned char* hash, unsigned int* hash_len);
void print_base64(const unsigned char* data, size_t len);
unsigned char* enc_AES(unsigned char* data, long* size, char* key, long* mi_size);
unsigned char* dec_AES(unsigned char* data, long* size, char* key, long* ming_size);
unsigned char* enc_RSA(unsigned char* data, long* size, unsigned char* public_key, long* mi_size);
unsigned char* dec_RSA(unsigned char* data, long* size, unsigned char* private_key, long* ming_size);
void file_write(const char* path, unsigned char* data, long size);