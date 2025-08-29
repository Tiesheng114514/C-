#include "enc_dec.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#pragma comment(lib,"C:\\OpenSSL64\\lib\\VC\\x64\\MT\\libcrypto.lib")
#pragma comment(lib,"C:\\OpenSSL64\\lib\\VC\\x64\\MT\\libssl.lib")

//��������iv(�̶�)
unsigned char iv[16] = {
0x6e,0xbb,0xff,0xf9,
0xea,0x1b,0x3c,0xac,
0x4b,0x2a,0x6f,0x4f,
0x45,0xf2,0xb3,0xa4 };

//���ļ� path��·����size���ļ����ȣ�����ֵ���ļ�
unsigned char* file_read(const char* path, long* size) {

	FILE* fp = fopen(path, "rb");
	fseek(fp, 0, SEEK_END);  // �ƶ����ļ�ĩβ
	*size = ftell(fp); // ��ȡ�ļ�����
	fseek(fp, 0, SEEK_SET);  // �ƻ��ļ���ͷ

	unsigned char* data = malloc(*size);

	size_t read = fread(data, 1, *size, fp);

	fclose(fp);

	return data;
}

//sha-256�㷨 data��ԭ����,size��ԭ���ݳ��ȣ�hash��������ݹ�ϣ��hash_len��������ݹ�ϣ���ȣ�����ֵ����
void SHA_256(const unsigned char* data, size_t size, unsigned char* hash, unsigned int* hash_len) {
	// 1. ������ϢժҪ������
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();

	// 2. ��ȡSHA-256�㷨�ṹ��
	const EVP_MD* md = EVP_sha256();

	// 3. ��ʼ��ժҪ����������
	EVP_DigestInit_ex(ctx, md, NULL);

	// 4. ������ݵ���ϣ���㣨�ɶ�ε��ô�����������
	EVP_DigestUpdate(ctx, data, size);

	// 5. ��ɹ�ϣ���㣬������
	//    - hash:     ���չ�ϣ����Ļ�����
	//    - hash_len: ���ع�ϣ�����ʵ�ʳ��ȣ�SHA-256Ϊ32�ֽڣ�
	EVP_DigestFinal_ex(ctx, hash, hash_len);

	// 6. �ͷ���������Դ
	EVP_MD_CTX_free(ctx);
}

// Base64����
void print_base64(const unsigned char* data, size_t len) {
	BIO* bio, * b64;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_push(b64, bio);

	BIO_write(b64, data, len);
	BIO_flush(b64);

	BIO_free_all(b64);
	printf("\n");
}

//AES���� data��ԭ���ݣ�size��ԭ���ݳ��ȣ�key����Կ��mi_size���������ݳ��ȣ�����ֵ����������
unsigned char* enc_AES(unsigned char* data, long* size, char* key, long* mi_size) {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	// ׼����������Կ��������AES-256��Ҫ32�ֽ���Կ��
	unsigned char real_key[32] = { 0 };
	unsigned char hash[32];
	unsigned int hash_len = 0;

	// �޸���ֱ��ʹ�û�����������ָ��
	SHA_256((const unsigned char*)key, strlen(key), hash, &hash_len);
	memcpy(real_key, hash, 32);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		printf("�����޷���������������\n");
		return NULL;
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, real_key, iv) != 1) {
		printf("���ܳ�ʼ��ʧ��\n");
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}

	int block_size = EVP_CIPHER_CTX_block_size(ctx);
	int out_len;
	int ciphertext_len = 0;

	// �����㹻��Ļ��������������ռ䣩
	unsigned char* ciphertext = (unsigned char*)malloc(*size + block_size);
	if (!ciphertext) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}

	// ִ�м���
	if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, data, (int)*size) != 1) {
		printf("���ܸ���ʧ��\n");
		free(ciphertext);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	ciphertext_len = out_len;

	if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len) != 1) {
		printf("�������ʧ��\n");
		free(ciphertext);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	ciphertext_len += out_len;

	*mi_size = ciphertext_len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext;
}

//AES���� data���������ݣ�size��ԭ�������ݳ��ȣ�key����Կ��ming_size���������ݳ��ȣ�����ֵ����������
unsigned char* dec_AES(unsigned char* data, long* size, char* key, long* ming_size) {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	// ׼����������Կ������
	unsigned char real_key[32] = { 0 };
	unsigned char hash[32];
	unsigned int hash_len = 0;

	// �޸���ֱ��ʹ�û�����������ָ��
	SHA_256((const unsigned char*)key, strlen(key), hash, &hash_len);
	memcpy(real_key, hash, 32);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		printf("�����޷���������������\n");
		return NULL;
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, real_key, iv) != 1) {
		printf("���ܳ�ʼ��ʧ��\n");
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}

	int out_len;
	int plaintext_len = 0;
	int block_size = EVP_CIPHER_CTX_block_size(ctx);

	// �����㹻��Ļ��������������ռ䣩
	unsigned char* plaintext = (unsigned char*)malloc(*size + block_size);
	if (!plaintext) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}

	// ִ�н���
	if (EVP_DecryptUpdate(ctx, plaintext, &out_len, data, (int)*size) != 1) {
		printf("���ܸ���ʧ��\n");
		free(plaintext);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	plaintext_len = out_len;

	if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &out_len) != 1) {
		printf("�������ʧ��\n");
		free(plaintext);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	plaintext_len += out_len;

	*ming_size = plaintext_len;
	EVP_CIPHER_CTX_free(ctx);

	// ���ƽ��ܺ�����ݵ���ȷ��С�Ļ�����
	unsigned char* result = (unsigned char*)malloc(plaintext_len);
	if (!result) {
		free(plaintext);
		return NULL;
	}
	memcpy(result, plaintext, plaintext_len);
	free(plaintext);

	return result;
}

//RSA��Կ�� public_key����Կ��private_key��˽Կ������ֵ����
void RSA_key(unsigned char** public_key, unsigned char** private_key) {
	EVP_PKEY* pkey = EVP_RSA_gen(2048);
	if (!pkey) {
		fprintf(stderr, "Error generating RSA key\n");
		return;
	}

	BIO* bio_pub = BIO_new(BIO_s_mem());
	BIO* bio_priv = BIO_new(BIO_s_mem());

	if (!bio_pub || !bio_priv) {
		fprintf(stderr, "Error creating BIO\n");
		goto cleanup;
	}

	if (PEM_write_bio_PUBKEY(bio_pub, pkey) != 1 ||
		PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
		fprintf(stderr, "Error writing keys\n");
		goto cleanup;
	}

	long pub_len = BIO_pending(bio_pub);
	long priv_len = BIO_pending(bio_priv);

	*public_key = (unsigned char*)malloc(pub_len + 1);
	*private_key = (unsigned char*)malloc(priv_len + 1);

	if (!*public_key || !*private_key) {
		fprintf(stderr, "Memory allocation failed\n");
		goto cleanup;
	}

	BIO_read(bio_pub, *public_key, pub_len);
	BIO_read(bio_priv, *private_key, priv_len);

	(*public_key)[pub_len] = '\0';
	(*private_key)[priv_len] = '\0';

cleanup:
	if (bio_pub) BIO_free(bio_pub);
	if (bio_priv) BIO_free(bio_priv);
	if (pkey) EVP_PKEY_free(pkey);
}

//RSA���� data��ԭ���ݣ�size��ԭ���ݳ��ȣ�public_key����Կ��mi_size���������ݳ��ȣ�����ֵ����������
unsigned char* enc_RSA(unsigned char* data, long* size, unsigned char* public_key, long* mi_size) {
	BIO* bio = BIO_new_mem_buf(public_key, -1);
	if (!bio) {
		fprintf(stderr, "Error creating BIO for public key\n");
		return NULL;
	}

	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (!pkey) {
		fprintf(stderr, "Error loading public key\n");
		return NULL;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		fprintf(stderr, "Error creating encryption context\n");
		EVP_PKEY_free(pkey);
		return NULL;
	}

	if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		fprintf(stderr, "Encryption setup failed\n");
		goto cleanup;
	}

	size_t outlen;
	if (EVP_PKEY_encrypt(ctx, NULL, &outlen, data, (size_t)*size) <= 0) {
		fprintf(stderr, "Error getting output size\n");
		goto cleanup;
	}

	unsigned char* encrypted = NULL;
	encrypted = (unsigned char*)malloc(outlen);
	if (!encrypted) {
		fprintf(stderr, "Memory allocation failed\n");
		goto cleanup;
	}

	if (EVP_PKEY_encrypt(ctx, encrypted, &outlen, data, (size_t)*size) <= 0) {
		fprintf(stderr, "Encryption failed\n");
		free(encrypted);
		encrypted = NULL;
		goto cleanup;
	}

	*mi_size = (long)outlen;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return encrypted;
}


//RSA���� data���������ݣ�size��ԭ�������ݳ��ȣ�public_key����Կ��private_key��˽Կ��ming_size���������ݳ��ȣ�����ֵ����������
unsigned char* dec_RSA(unsigned char* data, long* size, unsigned char* private_key, long* ming_size) {
	BIO* bio_priv = BIO_new_mem_buf(private_key, -1);
	if (!bio_priv) {
		fprintf(stderr, "Error creating BIO for private key\n");
		return NULL;
	}

	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio_priv, NULL, NULL, NULL);
	BIO_free(bio_priv);

	if (!pkey) {
		fprintf(stderr, "Error loading private key\n");
		return NULL;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		fprintf(stderr, "Error creating decryption context\n");
		EVP_PKEY_free(pkey);
		return NULL;
	}

	if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		fprintf(stderr, "Decryption setup failed\n");
		goto cleanup;
	}

	size_t outlen;
	if (EVP_PKEY_decrypt(ctx, NULL, &outlen, data, (size_t)*size) <= 0) {
		fprintf(stderr, "Error getting output size\n");
		goto cleanup;
	}

	unsigned char* decrypted = NULL;
  decrypted = (unsigned char*)malloc(outlen);
	if (!decrypted) {
		fprintf(stderr, "Memory allocation failed\n");
		goto cleanup;
	}

	if (EVP_PKEY_decrypt(ctx, decrypted, &outlen, data, (size_t)*size) <= 0) {
		fprintf(stderr, "Decryption failed\n");
		free(decrypted);
		decrypted = NULL;
		goto cleanup;
	}

	*ming_size = (long)outlen;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return decrypted;
}

//д�ļ� path��·����data���ļ���size���ļ����ȣ�����ֵ����
void file_write(const char* path, unsigned char* data, long size) {
	FILE* fwp = fopen(path, "wb");
	size_t write = fwrite(data, 1, size, fwp);

	fclose(fwp);

}
