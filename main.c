#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

// A multiple of AES_SIZE_BLOCK
#define DATA_SIZE 8192

static inline void memrand(void *dst, size_t n)
{
	srand((unsigned int)clock());

	for (size_t i = 0; i < n; ++i)
		*((uint8_t *)dst + i) = rand();
}

static inline void hex(void *src, size_t n, int end)
{
	for (size_t i = 0; i < n; ++i)
		printf(" %02x", *((uint8_t *)src + i));

	if (end != EOF)
		putchar(end);
}

static void test_mode_ecb(uint8_t *);
static void test_mode_cbc(uint8_t *);

int main(void)
{
	uint8_t data[DATA_SIZE];

	memrand(data, DATA_SIZE);

	puts("+ Details");
	printf("\t      Key size : %u bits\n", AES_SIZE_KEY * 8);
	printf("\tPlaintext size : %u bytes\n\n", DATA_SIZE);

	puts("+ ECB mode");
	test_mode_ecb(data);

	putchar('\n');

	puts("+ CBC mode");
	test_mode_cbc(data);

	return 0;
}

static void test_mode_ecb(uint8_t *data)
{
	uint8_t tmp[DATA_SIZE];
	uint8_t key[AES_SIZE_KEY];

	struct aes_ctx ectx, dctx;

	memrand(key, AES_SIZE_KEY);

	printf("\t       Key :");
	hex(key, AES_SIZE_KEY, '\n');

	aes_ecb_init(&ectx, key);
	aes_ecb_init(&dctx, key);

	memcpy(tmp, data, DATA_SIZE);

	printf("\t Plaintext :");
	hex(tmp, AES_SIZE_BLOCK, EOF); puts(" ..");

	aes_ecb_encrypt(&ectx, tmp, DATA_SIZE);

	printf("\tCiphertext :");
	hex(tmp, AES_SIZE_BLOCK, EOF); puts(" ..");

	aes_ecb_decrypt(&dctx, tmp, DATA_SIZE);

	printf("\tDeciphered :");
	hex(tmp, AES_SIZE_BLOCK, EOF); puts(" ..");

	if (memcmp(data, tmp, DATA_SIZE))
		puts("\n\t! Decryption failed");
}

static void test_mode_cbc(uint8_t *data)
{
	uint8_t tmp[DATA_SIZE];

	uint8_t iv [AES_SIZE_BLOCK];
	uint8_t key[AES_SIZE_KEY];

	struct aes_ctx ectx, dctx;

	memrand(iv,  AES_SIZE_BLOCK);
	memrand(key, AES_SIZE_KEY);

	printf("\t        IV :");
	hex(iv, AES_SIZE_BLOCK, '\n');

	printf("\t       Key :");
	hex(key, AES_SIZE_KEY, '\n');

	aes_cbc_init(&ectx, key, iv);
	aes_cbc_init(&dctx, key, iv);

	memcpy(tmp, data, DATA_SIZE);

	printf("\t Plaintext :");
	hex(tmp, AES_SIZE_BLOCK, EOF); puts(" ..");

	aes_cbc_encrypt(&ectx, tmp, DATA_SIZE);

	printf("\tCiphertext :");
	hex(tmp, AES_SIZE_BLOCK, EOF); puts(" ..");

	aes_cbc_decrypt(&dctx, tmp, DATA_SIZE);

	printf("\tDeciphered :");
	hex(tmp, AES_SIZE_BLOCK, EOF); puts(" ..");

	if (memcmp(data, tmp, DATA_SIZE))
		puts("\n\t! Decryption failed");
}
