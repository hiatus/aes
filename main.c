#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "aes.h"


#define SIZE_READ 32768

#ifdef AES_MODE_ECB
	#define MODE_ECB 0
#endif
#ifdef AES_MODE_CBC
	#define MODE_CBC 1
#endif


static const char _banner[] =
#if defined(AES128)
"aes-128 [options]\n"
#elif defined(AES192)
"aes-192 [options]\n"
#elif defined(AES256)
"aes-256 [options]\n"
#endif
"	-h         this\n"
"	-d         decrypt instead of encrypting\n"
"	-m [mode]  AES mode (cbc or ecb)\n"
#if defined(AES128)
"	-k [file]  read AES key from [file] (16 bytes)\n"
#elif defined(AES192)
"	-k [file]  read AES key from [file] (24 bytes)\n"
#elif defined(AES256)
"	-k [file]  read AES key from [file] (32 bytes)\n"
#endif
"	-i [file]  read AES initialization vector from [file] (16 bytes in length)\n";


static int _get_mode(const char *mode);
static int _read_bytes(uint8_t *buffer, const char *path, size_t len);

int main(int argc, char **argv)
{
	int opt;
	int ret = 0;
	int mode = -1;

	size_t len;

	bool decrypt = false;

	struct AESContext ctx;

	FILE *in = stdin;

	uint8_t key[AES_SIZE_KEY];
	uint8_t iv[AES_SIZE_BLOCK];
	uint8_t buffer[SIZE_READ];

	void (*aes_function)(struct AESContext *, void *, size_t);

	memset(key, 0x00, AES_SIZE_KEY);
	memset(iv, 0x00, AES_SIZE_BLOCK);

	while ((opt = getopt(argc, argv, ":hdm:k:i:")) != -1) {
		switch (opt) {
			case 'h':
				fputs(_banner, stderr);
				return ret;

			case 'd':
				decrypt = true;
				break;

			case 'm':
				if ((mode = _get_mode(optarg)) < 0) {
					fprintf(stderr, "[-] Unavailable AES mode '%s'\n", optarg);
					return 1;
				}

				break;

			case 'k':
				if (_read_bytes(key, optarg, AES_SIZE_KEY)) {
					perror("[!] Failed to read key file");
					return 1;
				}

				break;

			case 'i':
				if (_read_bytes(iv, optarg, AES_SIZE_BLOCK)) {
					perror("[!] Failed to read IV file");
					return 1;
				}

				break;
			
			case ':':
				fprintf(stderr, "[!] Option '%c' requires an argument\n", optopt);
				return 1;

			case '?':
				fprintf(stderr, "[!] Invalid option '%c'\n", optopt);
				return 1;
		}
	}

	if (mode < 0) {
		fputs("[!] No AES mode specified\n", stderr);
		return 1;
	}

	for (int i = 0; i < AES_SIZE_KEY && ! key[i]; ++i) {
		if (i + 1 == AES_SIZE_KEY) {
			fputs("[!] No AES key provided\n", stderr);
			return 1;
		}
	}

	#ifdef AES_MODE_CBC
	if (mode == MODE_CBC) {
		for (int i = 0; i < AES_SIZE_BLOCK && ! iv[i]; ++i) {
			if (i + 1 == AES_SIZE_BLOCK) {
				fputs("[!] No AES IV provided\n", stderr);
				return 1;
			}
		}
	}
	#endif

	if (optind < argc) {
		if (! (in = fopen(argv[optind], "r"))) {
			perror("[!] Failed to open input file");
			return 1;
		}
	}

	#ifdef AES_MODE_ECB
	if (mode == MODE_ECB) {
		aes_ecb_init(&ctx, key);
		aes_function = (decrypt) ? aes_ecb_decrypt : aes_ecb_encrypt;
	}
	#endif

	#ifdef AES_MODE_CBC
	if (mode == MODE_CBC) {
		aes_cbc_init(&ctx, key, iv);
		aes_function = (decrypt) ? aes_cbc_decrypt : aes_cbc_encrypt;
	}
	#endif

	while ((len = fread(buffer, 1, SIZE_READ, in)) > 0) {
		aes_function(&ctx, buffer, len);

		if (fwrite(buffer, 1, len, stdout) != len) {
			perror("[!] Failed to write all blocks");

			ret = 1;
			break;
		}
	}

	if (in && in != stdin)
		fclose(in);

	return ret;
}

int _get_mode(const char *mode)
{
	#ifdef AES_MODE_ECB
	if (! strcmp(mode, "ecb"))
		return MODE_ECB;
	#endif

	#ifdef AES_MODE_CBC
	if (! strcmp(mode, "cbc"))
		return MODE_CBC;
	#endif

	return -1;
}

int _read_bytes(uint8_t *buffer, const char *path, size_t len)
{
	int ret = 0;
	FILE *fp;

	if (! (fp = fopen(path, "r")))
		return 1;

	if (fread(buffer, 1, len, fp) != len)
		ret = 1;

	fclose(fp);
	return ret;
}
