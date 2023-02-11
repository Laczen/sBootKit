#ifndef CRYPTO_SHA256_TVECTORS_H_
#define CRYPTO_SHA256_TVECTORS_H_

#ifdef __cplusplus
extern "C" {
#endif

int crypto_sha256_testcnt(void);
int crypto_sha256_test(int index);

int crypto_hmac_sha256_testcnt(void);
int crypto_hmac_sha256_test(int index);

int crypto_hkdf_sha256_testcnt(void);
int crypto_hkdf_sha256_test(int index);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_SHA256_TVECTORS_H_ */