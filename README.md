aes
===
Portable and fast (enough) implementation of the Rijndael cipher in ECB and CBC modes.


API
---
The default `aes.h` header defines the key size as 128 bits and enables both ECB and CBC functions.

```
#define AES_ECB_MODE
#define AES_CBC_MODE

#define AES128
// #define AES192
// #define AES256

#if defined(AES_ECB_MODE)
void aes_ecb_init(struct AESContext *ctx, const uint8_t *key);

void aes_ecb_encrypt(const struct AESContext *ctx, void *buffer, size_t len);
void aes_ecb_decrypt(const struct AESContext *ctx, void *buffer, size_t len);
#endif

#if defined(AES_CBC_MODE)
void aes_cbc_init(struct AESContext *ctx, const uint8_t *key, const uint8_t *iv);

void aes_cbc_encrypt(struct AESContext *ctx, void *buffer, size_t len);
void aes_cbc_decrypt(struct AESContext *ctx, void *buffer, size_t len);
#endif
#endif
```

In order to keep the code small and portable, no padding is done. Therefore, in bytes, the size of
`key` must equal `AES_SIZE_KEY`, the size of `iv` must equal `AES_SIZE_BLOCK` (16) and the size of
`buffer` (`len`) must be a multiple of `AES_SIZE_BLOCK` (16).


CLI
---
A CLI program is provided along with the AES code. It's characteristics (key size and supported AES
modes) will depend on what is defined in `aes.h`.

- Clone the repository
```
$ git clone https://github.com/hiatus/aes.git
```

- Run `make` to compile the binary
```
$ cd aes && make
```

- Run the program
```
$ ./bin/aes -h
aes-128 [options] [file]
	-h         this
	-d         decrypt instead of encrypting
	-m [mode]  AES mode (cbc or ecb)
	-k [file]  read AES key from [file] (16 bytes in length)
	-i [file]  read AES initialization vector from [file] (16 bytes in length)
```

**Note**: this CLI is only meant for testing and usability purposes only. It does not implement any
key derivation functions and does not generate the IV for CBC mode. Both key and IV are expected to
be generated externally with the appropriate sizes and provided as file arguments. Input padding is
also not implemented; that is expected to be done externally as well, so make sure the input length
is divisible by `AES_SIZE_BLOCK`.


References
---------
- https://github.com/kokke/tiny-AES-c
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
