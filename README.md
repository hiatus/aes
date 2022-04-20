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
void aes_ecb_init(struct aes_ctx *ctx, const uint8_t *key);

void aes_ecb_encrypt(const struct aes_ctx *ctx, void *buffer, size_t len);
void aes_ecb_decrypt(const struct aes_ctx *ctx, void *buffer, size_t len);
#endif

#if defined(AES_CBC_MODE)
void aes_cbc_init(struct aes_ctx *ctx, const uint8_t *key, const uint8_t *iv);

void aes_cbc_encrypt(struct aes_ctx *ctx, void *buffer, size_t len);
void aes_cbc_decrypt(struct aes_ctx *ctx, void *buffer, size_t len);
#endif
#endif
```

In order to keep the code small and portable, no padding is done. Therefore, in bytes, the size of `key` must equal `AES_SIZE_KEY`, the size of `iv` must equal `AES_SIZE_BLOCK` (16) and the size of `buffer` (`len`) must be a multiple of `AES_SIZE_BLOCK` (16).

Testing
-------
- Compile the test binary
```
$ git clone https://github.com/hiatus/aes.git && cd aes && make
```

- Run it
```
$ ./bin/aes-test
```

References
---------
- https://github.com/kokke/tiny-AES-c
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
