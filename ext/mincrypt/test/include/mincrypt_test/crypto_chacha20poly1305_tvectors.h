#ifndef CRYPTO_CHACHA20POLY1305_TVECTORS_H_
#define CRYPTO_CHACHA20POLY1305_TVECTORS_H_

#ifdef __cplusplus
extern "C" {
#endif

int crypto_poly1305_testcnt(void);
int crypto_poly1305_test(int index);

int crypto_chacha20_testcnt(void);
int crypto_chacha20_test(int index);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CHACHA20POLY1305_TVECTORS_H_ */