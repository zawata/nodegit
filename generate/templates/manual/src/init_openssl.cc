#include <dlfcn.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <uv.h>

#ifdef __linux__
#include <openssl/ossl_typ.h>


// If we export this symbols we could cause export issues for
// this file is only for linux so far so this macro doesn't need to be more accomodating
#ifdef __GNUC__
#define __no_export __attribute__ ((visibility ("hidden")))
#endif

//the function pointers need to be declared with C linkage otherwise the names will be mangled by the c++ compiler
// TODO - jza: if this list gets any bigger, it'd probably be a good idea to just generasste it.
//             I've already got a python script to write the code, making json would be easy and
//             the template would be dead simple.
extern "C" {

// BN_ types
typedef unsigned long long BN_ULONG;


// CRYPTO_ types
typedef struct crypto_threadid_st {
    int dummy;
} CRYPTO_THREADID;

#define CRYPTO_LOCK 1


// DSA_ types
typedef struct DSA_SIG_st DSA_SIG;


// EC_ types
typedef struct ec_group_st EC_GROUP;
typedef struct ec_point_st EC_POINT;

typedef enum {
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;


// ECDSA_ types
typedef struct ECDSA_SIG_st ECDSA_SIG;


// PEM_ types
typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);



// BIO_ functions
__no_export long (*__BIO_ctrl)(BIO *bp, int cmd, long larg, void *parg);
__no_export long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg) {
  return __BIO_ctrl(bp, cmd, larg, parg);
}

__no_export int (*__BIO_free)(BIO *a);
__no_export int BIO_free(BIO *a) {
  return __BIO_free(a);
}

__no_export BIO *(*__BIO_new_file)(const char *filename, const char *mode);
__no_export BIO *BIO_new_file(const char *filename, const char *mode) {
  return __BIO_new_file(filename, mode);
}

__no_export BIO *(*__BIO_new_mem_buf)(const void *buf, int len);
__no_export BIO *BIO_new_mem_buf(const void *buf, int len) {
  return __BIO_new_mem_buf(buf, len);
}


// BN_ functions
__no_export BN_CTX *(*__BN_CTX_new)();
__no_export BN_CTX *BN_CTX_new() {
  return __BN_CTX_new();
}

__no_export void (*__BN_CTX_free)(BN_CTX *c);
__no_export void BN_CTX_free(BN_CTX *c) {
  return __BN_CTX_free(c);
}

__no_export BIGNUM *(*__BN_bin2bn)(const unsigned char *s, int len, BIGNUM *ret);
__no_export BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret) {
  return __BN_bin2bn(s, len, ret);
}

__no_export int (*__BN_bn2bin)(const BIGNUM *a, unsigned char *to);
__no_export int BN_bn2bin(const BIGNUM *a, unsigned char *to) {
  return __BN_bn2bin(a, to);
}

__no_export void (*__BN_clear_free)(BIGNUM *a);
__no_export void BN_clear_free(BIGNUM *a) {
  return __BN_clear_free(a);
}

__no_export int (*__BN_div)(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx);
__no_export int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx) {
  return __BN_div(dv, rem, a, d, ctx);
}

__no_export int (*__BN_mod_exp)(BIGNUM *r, BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx);
__no_export int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx) {
  return __BN_mod_exp(r, a, p, m, ctx);
}

__no_export BIGNUM *(*__BN_new)();
__no_export BIGNUM *BN_new() {
  return __BN_new();
}

__no_export int (*__BN_num_bits)(const BIGNUM *a);
__no_export int BN_num_bits(const BIGNUM *a) {
  return __BN_num_bits(a);
}

__no_export int (*__BN_rand)(BIGNUM *rnd, int bits, int top, int bottom);
__no_export int BN_rand(BIGNUM *rnd, int bits, int top, int bottom) {
  return __BN_rand(rnd, bits, top, bottom);
}

__no_export int (*__BN_set_word)(BIGNUM *a, BN_ULONG w);
__no_export int BN_set_word(BIGNUM *a, BN_ULONG w) {
  return __BN_set_word(a, w);
}

__no_export int (*__BN_sub)(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
__no_export int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
  return __BN_sub(r, a, b);
}

__no_export const BIGNUM *(*__BN_value_one)();
__no_export const BIGNUM *BN_value_one() {
  return __BN_value_one();
}


// CRYPTO_ functions
//These are static because otherwise they will interfere with the imported symbols in libgit2/src/streams/openssl_dynamic.c
//They're also only used internally
__no_export static void (*__CRYPTO_THREADID_set_numeric)(CRYPTO_THREADID *id, unsigned long val);
__no_export static void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val) {
  return __CRYPTO_THREADID_set_numeric(id, val);
}

__no_export static int (*__CRYPTO_THREADID_set_callback)(void (*threadid_func)(CRYPTO_THREADID *));
__no_export static int CRYPTO_THREADID_set_callback(void (*threadid_func)(CRYPTO_THREADID *)) {
  return __CRYPTO_THREADID_set_callback(threadid_func);
}

__no_export static int (*__CRYPTO_num_locks)();
__no_export static int CRYPTO_num_locks() {
  return __CRYPTO_num_locks();
}

__no_export static void (*__CRYPTO_set_locking_callback)(void (*locking_function)(int mode, int n, const char *file, int line));
__no_export static void CRYPTO_set_locking_callback(void (*locking_function)(int mode, int n, const char *file, int line)) {
  return __CRYPTO_set_locking_callback(locking_function);
}


// DSA_ functions
__no_export void (*__DSA_SIG_free)(DSA_SIG *a);
__no_export void DSA_SIG_free(DSA_SIG *a) {
  return __DSA_SIG_free(a);
}

__no_export void (*__DSA_SIG_get0)(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
__no_export void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
  return __DSA_SIG_get0(sig, pr, ps);
}

__no_export DSA_SIG *(*__DSA_SIG_new)();
__no_export DSA_SIG *DSA_SIG_new() {
  return __DSA_SIG_new();
}

__no_export int (*__DSA_SIG_set0)(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);
__no_export int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
  return __DSA_SIG_set0(sig, r, s);
}

__no_export DSA_SIG *(*__DSA_do_sign)(const unsigned char *dgst, int dlen, DSA *dsa);
__no_export DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa) {
  return __DSA_do_sign(dgst, dlen, dsa);
}

__no_export int (*__DSA_do_verify)(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa);
__no_export int DSA_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa) {
  return __DSA_do_verify(dgst, dgst_len, sig, dsa);
}

__no_export void (*__DSA_free)(DSA *r);
__no_export void DSA_free(DSA *r) {
  return __DSA_free(r);
}

__no_export void (*__DSA_get0_key)(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key);
__no_export void DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key) {
  return __DSA_get0_key(d, pub_key, priv_key);
}

__no_export void (*__DSA_get0_pqg)(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
__no_export void DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
  return __DSA_get0_pqg(d, p, q, g);
}

__no_export DSA *(*__DSA_new)();
__no_export DSA *DSA_new() {
  return __DSA_new();
}

__no_export int (*__DSA_set0_key)(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key);
__no_export int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key) {
  return __DSA_set0_key(d, pub_key, priv_key);
}

__no_export int (*__DSA_set0_pqg)(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
__no_export int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
  return __DSA_set0_pqg(d, p, q, g);
}


// EC_ functions
__no_export int (*__EC_GROUP_get_curve_name)(const EC_GROUP *group);
__no_export int EC_GROUP_get_curve_name(const EC_GROUP *group) {
  return __EC_GROUP_get_curve_name(group);
}

__no_export int (*__EC_GROUP_get_degree)(const EC_GROUP *group);
__no_export int EC_GROUP_get_degree(const EC_GROUP *group) {
  return __EC_GROUP_get_degree(group);
}

__no_export void (*__EC_KEY_free)(EC_KEY *key);
__no_export void EC_KEY_free(EC_KEY *key) {
  return __EC_KEY_free(key);
}

__no_export int (*__EC_KEY_generate_key)(EC_KEY *key);
__no_export int EC_KEY_generate_key(EC_KEY *key) {
  return __EC_KEY_generate_key(key);
}

__no_export const EC_GROUP *(*__EC_KEY_get0_group)(const EC_KEY *key);
__no_export const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key) {
  return __EC_KEY_get0_group(key);
}

__no_export const EC_POINT *(*__EC_KEY_get0_public_key)(const EC_KEY *key);
__no_export const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key) {
  return __EC_KEY_get0_public_key(key);
}

__no_export EC_KEY *(*__EC_KEY_new_by_curve_name)(int nid);
__no_export EC_KEY *EC_KEY_new_by_curve_name(int nid) {
  return __EC_KEY_new_by_curve_name(nid);
}

__no_export int (*__EC_KEY_set_private_key)(EC_KEY *key, const BIGNUM *prv);
__no_export int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv) {
  return __EC_KEY_set_private_key(key, prv);
}

__no_export int (*__EC_KEY_set_public_key)(EC_KEY *key, const EC_POINT *pub);
__no_export int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub) {
  return __EC_KEY_set_public_key(key, pub);
}

__no_export void (*__EC_POINT_free)(EC_POINT *point);
__no_export void EC_POINT_free(EC_POINT *point) {
  return __EC_POINT_free(point);
}

__no_export EC_POINT *(*__EC_POINT_new)(const EC_GROUP *group);
__no_export EC_POINT *EC_POINT_new(const EC_GROUP *group) {
  return __EC_POINT_new(group);
}

__no_export int (*__EC_POINT_oct2point)(const EC_GROUP *group, EC_POINT *p, const unsigned char *buf, size_t len, BN_CTX *ctx);
__no_export int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p, const unsigned char *buf, size_t len, BN_CTX *ctx) {
  return __EC_POINT_oct2point(group, p, buf, len, ctx);
}

__no_export size_t (*__EC_POINT_point2oct)(const EC_GROUP *group, const EC_POINT *p, point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX *ctx);
__no_export size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p, point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX *ctx) {
  return __EC_POINT_point2oct(group, p, form, buf, len, ctx);
}


// ECDSA_ functions
__no_export ECDSA_SIG *(*__ECDSA_SIG_new)();
__no_export ECDSA_SIG *ECDSA_SIG_new() {
  return __ECDSA_SIG_new();
}

__no_export int (*__ECDSA_SIG_set0)(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
__no_export int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {
  return __ECDSA_SIG_set0(sig, r, s);
}

__no_export int (*__ECDSA_do_verify)(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey);
__no_export int ECDSA_do_verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey) {
  return __ECDSA_do_verify(dgst, dgst_len, sig, eckey);
}

__no_export void (*__ECDSA_SIG_free)(ECDSA_SIG *sig);
__no_export void ECDSA_SIG_free(ECDSA_SIG *sig) {
  return __ECDSA_SIG_free(sig);
}

__no_export ECDSA_SIG *(*__ECDSA_do_sign)(const unsigned char *dgst, int dgst_len, EC_KEY *eckey);
__no_export ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len, EC_KEY *eckey) {
  return __ECDSA_do_sign(dgst, dgst_len, eckey);
}

__no_export void (*__ECDSA_SIG_get0)(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
__no_export void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
  return __ECDSA_SIG_get0(sig, pr, ps);
}


// ECDH_ functions
__no_export int (*__ECDH_compute_key)(void *out, size_t outlen, const EC_POINT *pub_key, const EC_KEY *ecdh, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
__no_export int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, const EC_KEY *ecdh, void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen)) {
  return __ECDH_compute_key(out, outlen, pub_key, ecdh, KDF);
}


// ENGINE_ functions
__no_export void (*__ENGINE_load_builtin_engines)();
__no_export void ENGINE_load_builtin_engines() {
  return __ENGINE_load_builtin_engines();
}

__no_export int (*__ENGINE_register_all_complete)();
__no_export int ENGINE_register_all_complete() {
  return __ENGINE_register_all_complete();
}


// EVP_ functions
__no_export void (*__EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *ctx);
__no_export void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx) {
  return __EVP_CIPHER_CTX_free(ctx);
}

__no_export void *(*__EVP_CIPHER_CTX_get_app_data)(const EVP_CIPHER_CTX *ctx);
__no_export void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx) {
  return __EVP_CIPHER_CTX_get_app_data(ctx);
}

__no_export int (*__EVP_CIPHER_CTX_key_length)(const EVP_CIPHER_CTX *ctx);
__no_export int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx) {
  return __EVP_CIPHER_CTX_key_length(ctx);
}

__no_export EVP_CIPHER_CTX *(*__EVP_CIPHER_CTX_new)();
__no_export EVP_CIPHER_CTX *EVP_CIPHER_CTX_new() {
  return __EVP_CIPHER_CTX_new();
}

__no_export void (*__EVP_CIPHER_CTX_set_app_data)(const EVP_CIPHER_CTX *ctx, void *data);
__no_export void EVP_CIPHER_CTX_set_app_data(const EVP_CIPHER_CTX *ctx, void *data) {
  return __EVP_CIPHER_CTX_set_app_data(ctx, data);
}

__no_export int (*__EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX *x, int padding);
__no_export int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding) {
  return __EVP_CIPHER_CTX_set_padding(x, padding);
}

__no_export void (*__EVP_CIPHER_meth_free)(EVP_CIPHER *cipher);
__no_export void EVP_CIPHER_meth_free(EVP_CIPHER *cipher) {
  return __EVP_CIPHER_meth_free(cipher);
}

__no_export EVP_CIPHER *(*__EVP_CIPHER_meth_new)(int cipher_type, int block_size, int key_len);
__no_export EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len) {
  return __EVP_CIPHER_meth_new(cipher_type, block_size, key_len);
}

__no_export int (*__EVP_CIPHER_meth_set_cleanup)(EVP_CIPHER *cipher, int (*cleanup)(EVP_CIPHER_CTX *));
__no_export int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher, int (*cleanup)(EVP_CIPHER_CTX *)) {
  return __EVP_CIPHER_meth_set_cleanup(cipher, cleanup);
}

__no_export int (*__EVP_CIPHER_meth_set_do_cipher)(EVP_CIPHER *cipher, int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl));
__no_export int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher, int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)) {
  return __EVP_CIPHER_meth_set_do_cipher(cipher, do_cipher);
}

__no_export int (*__EVP_CIPHER_meth_set_init)(EVP_CIPHER *cipher, int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc));
__no_export int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher, int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)) {
  return __EVP_CIPHER_meth_set_init(cipher, init);
}

__no_export int (*__EVP_CIPHER_meth_set_iv_length)(EVP_CIPHER *cipher, int iv_len);
__no_export int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len) {
  return __EVP_CIPHER_meth_set_iv_length(cipher, iv_len);
}

__no_export int (*__EVP_Cipher)(EVP_CIPHER_CTX *c, unsigned char *out, const unsigned char *in, unsigned int inl);
__no_export int EVP_Cipher(EVP_CIPHER_CTX *c, unsigned char *out, const unsigned char *in, unsigned int inl) {
  return __EVP_Cipher(c, out, in, inl);
}

__no_export int (*__EVP_CipherInit)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
__no_export int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc) {
  return __EVP_CipherInit(ctx, type, key, iv, enc);
}

__no_export int (*__EVP_DigestFinal)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
__no_export int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) {
  return __EVP_DigestFinal(ctx, md, s);
}

__no_export int (*__EVP_DigestInit)(EVP_MD_CTX *ctx, const EVP_MD *type);
__no_export int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
  return __EVP_DigestInit(ctx, type);
}

__no_export int (*__EVP_DigestSign)(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
__no_export int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
  return __EVP_DigestSign(ctx, sigret, siglen, tbs, tbslen);
}

__no_export int (*__EVP_DigestSignInit)(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
__no_export int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey) {
  return __EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

__no_export int (*__EVP_DigestUpdate)(EVP_MD_CTX *ctx, const void *d, size_t cnt);
__no_export int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
  return __EVP_DigestUpdate(ctx, d, cnt);
}

__no_export int (*__EVP_DigestVerify)(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
__no_export int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen) {
  return __EVP_DigestVerify(ctx, sigret, siglen, tbs, tbslen);
}

__no_export int (*__EVP_DigestVerifyInit)(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
__no_export int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey) {
  return __EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

__no_export int (*__EVP_EncryptInit)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
__no_export int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv) {
  return __EVP_EncryptInit(ctx, type, key, iv);
}

__no_export int (*__EVP_EncryptUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
__no_export int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
  return __EVP_EncryptUpdate(ctx, out, outl, in, inl);
}

__no_export void (*__EVP_MD_CTX_free)(EVP_MD_CTX *ctx);
__no_export void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
  return __EVP_MD_CTX_free(ctx);
}

__no_export EVP_MD_CTX *(*__EVP_MD_CTX_new)();
__no_export EVP_MD_CTX *EVP_MD_CTX_new() {
  return __EVP_MD_CTX_new();
}

__no_export void (*__EVP_PKEY_CTX_free)(EVP_PKEY_CTX *ctx);
__no_export void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx) {
  return __EVP_PKEY_CTX_free(ctx);
}

__no_export EVP_PKEY_CTX *(*__EVP_PKEY_CTX_new)(EVP_PKEY *pkey, ENGINE *e);
__no_export EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e) {
  return __EVP_PKEY_CTX_new(pkey, e);
}

__no_export EVP_PKEY_CTX *(*__EVP_PKEY_CTX_new_id)(int id, ENGINE *e);
__no_export EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e) {
  return __EVP_PKEY_CTX_new_id(id, e);
}

__no_export int (*__EVP_PKEY_derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
__no_export int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
  return __EVP_PKEY_derive(ctx, key, keylen);
}

__no_export int (*__EVP_PKEY_derive_init)(EVP_PKEY_CTX *ctx);
__no_export int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx) {
  return __EVP_PKEY_derive_init(ctx);
}

__no_export int (*__EVP_PKEY_derive_set_peer)(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
__no_export int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer) {
  return __EVP_PKEY_derive_set_peer(ctx, peer);
}

__no_export void (*__EVP_PKEY_free)(EVP_PKEY *key);
__no_export void EVP_PKEY_free(EVP_PKEY *key) {
  return __EVP_PKEY_free(key);
}

__no_export DSA *(*__EVP_PKEY_get1_DSA)(EVP_PKEY *pkey);
__no_export DSA *EVP_PKEY_get1_DSA(EVP_PKEY *pkey) {
  return __EVP_PKEY_get1_DSA(pkey);
}

__no_export EC_KEY *(*__EVP_PKEY_get1_EC_KEY)(EVP_PKEY *pkey);
__no_export EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey) {
  return __EVP_PKEY_get1_EC_KEY(pkey);
}

__no_export RSA *(*__EVP_PKEY_get1_RSA)(EVP_PKEY *pkey);
__no_export RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey) {
  return __EVP_PKEY_get1_RSA(pkey);
}

__no_export int (*__EVP_PKEY_get_raw_private_key)(const EVP_PKEY *pkey, unsigned char *priv, size_t *len);
__no_export int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv, size_t *len) {
  return __EVP_PKEY_get_raw_private_key(pkey, priv, len);
}

__no_export int (*__EVP_PKEY_get_raw_public_key)(const EVP_PKEY *pkey, unsigned char *pub, size_t *len);
__no_export int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len) {
  return __EVP_PKEY_get_raw_public_key(pkey, pub, len);
}

__no_export int (*__EVP_PKEY_id)(const EVP_PKEY *pkey);
__no_export int EVP_PKEY_id(const EVP_PKEY *pkey) {
  return __EVP_PKEY_id(pkey);
}

__no_export int (*__EVP_PKEY_keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
__no_export int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) {
  return __EVP_PKEY_keygen(ctx, ppkey);
}

__no_export int (*__EVP_PKEY_keygen_init)(EVP_PKEY_CTX *ctx);
__no_export int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx) {
  return __EVP_PKEY_keygen_init(ctx);
}

__no_export EVP_PKEY *(*__EVP_PKEY_new)();
__no_export EVP_PKEY *EVP_PKEY_new() {
  return __EVP_PKEY_new();
}

__no_export EVP_PKEY *(*__EVP_PKEY_new_raw_private_key)(int type, ENGINE *e, const unsigned char *key, size_t keylen);
__no_export EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e, const unsigned char *key, size_t keylen) {
  return __EVP_PKEY_new_raw_private_key(type, e, key, keylen);
}

__no_export EVP_PKEY *(*__EVP_PKEY_new_raw_public_key)(int type, ENGINE *e, const unsigned char *key, size_t keylen);
__no_export EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e, const unsigned char *key, size_t keylen) {
  return __EVP_PKEY_new_raw_public_key(type, e, key, keylen);
}

__no_export int (*__EVP_PKEY_set1_DSA)(EVP_PKEY *pkey, DSA *key);
__no_export int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key) {
  return __EVP_PKEY_set1_DSA(pkey, key);
}

__no_export int (*__EVP_PKEY_set1_EC_KEY)(EVP_PKEY *pkey, EC_KEY *key);
__no_export int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key) {
  return __EVP_PKEY_set1_EC_KEY(pkey, key);
}

__no_export int (*__EVP_PKEY_set1_RSA)(EVP_PKEY *pkey, RSA *key);
__no_export int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key) {
  return __EVP_PKEY_set1_RSA(pkey, key);
}

__no_export const EVP_CIPHER *(*__EVP_aes_128_cbc)();
__no_export const EVP_CIPHER *EVP_aes_128_cbc() {
  return __EVP_aes_128_cbc();
}

__no_export const EVP_CIPHER *(*__EVP_aes_128_ctr)();
__no_export const EVP_CIPHER *EVP_aes_128_ctr() {
  return __EVP_aes_128_ctr();
}

__no_export const EVP_CIPHER *(*__EVP_aes_128_ecb)();
__no_export const EVP_CIPHER *EVP_aes_128_ecb() {
  return __EVP_aes_128_ecb();
}

__no_export const EVP_CIPHER *(*__EVP_aes_192_cbc)();
__no_export const EVP_CIPHER *EVP_aes_192_cbc() {
  return __EVP_aes_192_cbc();
}

__no_export const EVP_CIPHER *(*__EVP_aes_192_ctr)();
__no_export const EVP_CIPHER *EVP_aes_192_ctr() {
  return __EVP_aes_192_ctr();
}

__no_export const EVP_CIPHER *(*__EVP_aes_192_ecb)();
__no_export const EVP_CIPHER *EVP_aes_192_ecb() {
  return __EVP_aes_192_ecb();
}

__no_export const EVP_CIPHER *(*__EVP_aes_256_cbc)();
__no_export const EVP_CIPHER *EVP_aes_256_cbc() {
  return __EVP_aes_256_cbc();
}

__no_export const EVP_CIPHER *(*__EVP_aes_256_ctr)();
__no_export const EVP_CIPHER *EVP_aes_256_ctr() {
  return __EVP_aes_256_ctr();
}

__no_export const EVP_CIPHER *(*__EVP_aes_256_ecb)();
__no_export const EVP_CIPHER *EVP_aes_256_ecb() {
  return __EVP_aes_256_ecb();
}

__no_export const EVP_CIPHER *(*__EVP_bf_cbc)();
__no_export const EVP_CIPHER *EVP_bf_cbc() {
  return __EVP_bf_cbc();
}

__no_export const EVP_CIPHER *(*__EVP_cast5_cbc)();
__no_export const EVP_CIPHER *EVP_cast5_cbc() {
  return __EVP_cast5_cbc();
}

__no_export const EVP_CIPHER *(*__EVP_des_ede3_cbc)();
__no_export const EVP_CIPHER *EVP_des_ede3_cbc() {
  return __EVP_des_ede3_cbc();
}

__no_export const EVP_MD *(*__EVP_get_digestbyname)(const char *name);
__no_export const EVP_MD *EVP_get_digestbyname(const char *name) {
  return __EVP_get_digestbyname(name);
}

__no_export const EVP_MD *(*__EVP_md5)();
__no_export const EVP_MD *EVP_md5() {
  return __EVP_md5();
}

__no_export const EVP_CIPHER *(*__EVP_rc4)();
__no_export const EVP_CIPHER *EVP_rc4() {
  return __EVP_rc4();
}

__no_export const EVP_MD *(*__EVP_ripemd160)();
__no_export const EVP_MD *EVP_ripemd160() {
  return __EVP_ripemd160();
}

__no_export const EVP_MD *(*__EVP_sha1)();
__no_export const EVP_MD *EVP_sha1() {
  return __EVP_sha1();
}

__no_export const EVP_MD *(*__EVP_sha256)();
__no_export const EVP_MD *EVP_sha256() {
  return __EVP_sha256();
}

__no_export const EVP_MD *(*__EVP_sha512)();
__no_export const EVP_MD *EVP_sha512() {
  return __EVP_sha512();
}


// HMAC_ functions
__no_export void (*__HMAC_CTX_free)(HMAC_CTX *ctx);
__no_export void HMAC_CTX_free(HMAC_CTX *ctx) {
  return __HMAC_CTX_free(ctx);
}

__no_export HMAC_CTX *(*__HMAC_CTX_new)();
__no_export HMAC_CTX *HMAC_CTX_new() {
  return __HMAC_CTX_new();
}

__no_export int (*__HMAC_Final)(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
__no_export int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len) {
  return __HMAC_Final(ctx, md, len);
}

__no_export int (*__HMAC_Init_ex)(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
__no_export int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl) {
  return __HMAC_Init_ex(ctx, key, len, md, impl);
}

__no_export int (*__HMAC_Update)(HMAC_CTX *ctx, const unsigned char *data, size_t len);
__no_export int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len) {
  return __HMAC_Update(ctx, data, len);
}


// OPENSSL_ functions
__no_export unsigned int (*__OpenSSL_version_num)();
__no_export unsigned int OpenSSL_version_num() {
  return __OpenSSL_version_num();
}

__no_export void (*__OpenSSL_add_all_algorithms)();
__no_export void OpenSSL_add_all_algorithms() {
  return __OpenSSL_add_all_algorithms();
}

__no_export void (*__OpenSSL_add_all_ciphers)();
__no_export void OpenSSL_add_all_ciphers() {
  return __OpenSSL_add_all_ciphers();
}

__no_export void (*__OpenSSL_add_all_digests)();
__no_export void OpenSSL_add_all_digests() {
  return __OpenSSL_add_all_digests();
}


// PEM_ functions
__no_export DSA *(*__PEM_read_bio_DSAPrivateKey)(BIO *bp, DSA **x, pem_password_cb *cb, void *u);
__no_export DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **x, pem_password_cb *cb, void *u) {
  return __PEM_read_bio_DSAPrivateKey(bp, x, cb, u);
}

__no_export EC_KEY *(*__PEM_read_bio_ECPrivateKey)(BIO *out, EC_KEY **x, pem_password_cb *cb, void *u);
__no_export EC_KEY *PEM_read_bio_ECPrivateKey(BIO *out, EC_KEY **x, pem_password_cb *cb, void *u) {
  return __PEM_read_bio_ECPrivateKey(out, x, cb, u);
}

__no_export EVP_PKEY *(*__PEM_read_bio_PrivateKey)(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
__no_export EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
  return __PEM_read_bio_PrivateKey(bp, x, cb, u);
}

__no_export RSA *(*__PEM_read_bio_RSAPrivateKey)(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
__no_export RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u) {
  return __PEM_read_bio_RSAPrivateKey(bp, x, cb, u);
}


// RAND_ functions
__no_export int (*__RAND_bytes)(unsigned char *buf, int num);
__no_export int RAND_bytes(unsigned char *buf, int num) {
  return __RAND_bytes(buf, num);
}


// RSA_ functions
__no_export void (*__RSA_free)(RSA *r);
__no_export void RSA_free(RSA *r) {
  return __RSA_free(r);
}

__no_export void (*__RSA_get0_factors)(const RSA *r, const BIGNUM **p, const BIGNUM **q);
__no_export void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q) {
  return __RSA_get0_factors(r, p, q);
}

__no_export void (*__RSA_get0_key)(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
__no_export void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
  return __RSA_get0_key(r, n, e, d);
}

__no_export RSA *(*__RSA_new)();
__no_export RSA *RSA_new() {
  return __RSA_new();
}

__no_export int (*__RSA_set0_crt_params)(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
__no_export int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp) {
  return __RSA_set0_crt_params(r, dmp1, dmq1, iqmp);
}

__no_export int (*__RSA_set0_factors)(RSA *r, BIGNUM *p, BIGNUM *q);
__no_export int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q) {
  return __RSA_set0_factors(r, p, q);
}

__no_export int (*__RSA_set0_key)(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
__no_export int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
  return __RSA_set0_key(r, n, e, d);
}

__no_export int (*__RSA_sign)(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, RSA *rsa);
__no_export int RSA_sign(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, RSA *rsa) {
  return __RSA_sign(type, m, m_length, sigret, siglen, rsa);
}

__no_export int (*__RSA_size)(const RSA *rsa);
__no_export int RSA_size(const RSA *rsa) {
  return __RSA_size(rsa);
}

__no_export int (*__RSA_verify)(int type, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
__no_export int RSA_verify(int type, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, RSA *rsa) {
  return __RSA_verify(type, m, m_length, sigbuf, siglen, rsa);
}

} // extern "C"


static void *openssl_handle = nullptr;

bool __linux__load_openssl(void) {
  // With libgit2's dynamic openssl loading, we no longer need to compile against it but we do
  // still need access to some symbols here.
  // Additionally, because of the flags libgit2 passes to dlopen, node attempts to override various symbols
  // in libssl on load which could cause ABI issues for us later.
  // Theres 2 fixes for this problem
  //   1. recompile node such that it doesn't export libssl and libcrypto symbols and ship that with nodegit
  //   2. force an early dlopen call with RTLD_DEEPBIND set to make libssl prefer it's own symbols over node's
  // you tell me which one is easier
  if(!openssl_handle) {
    //replicate libgit2's dlopen logic with new flags
    if ((openssl_handle = dlopen("libssl.so.1.1", RTLD_NOW | RTLD_DEEPBIND)) == NULL &&
        (openssl_handle = dlopen("libssl.so.1.0.0", RTLD_NOW | RTLD_DEEPBIND)) == NULL &&
        (openssl_handle = dlopen("libssl.so.10", RTLD_NOW | RTLD_DEEPBIND)) == NULL) {
      openssl_handle = nullptr;
      return false;
    }
  }
  return true;
}

bool __linux_unload_openssl(void) {
  //TODO: should we dlclose?
  // according to https://pubs.opengroup.org/onlinepubs/000095399/functions/dlclose.html:
  //  "Although a dlclose() operation is not required to remove structures from an address space,
  //   neither is an implementation prohibited from doing so"

  return true;
}

// A function and macro to simplify symbol loading
#define load_symbol(sym, required) _load_symbol((void **)&__##sym, #sym, required)
void _load_symbol(void **ptr, const char *func, bool required) {
  *ptr = dlsym(openssl_handle, func);
  if(!*ptr && required) {
    fprintf(stderr, "error loading %s: %s\n", func, dlerror());
  }
}

bool __linux_load_symbols(void) {
  load_symbol(OpenSSL_version_num, true);

  bool is_version_1_0 = OpenSSL_version_num() < 0x10100000UL;

  // starting with openssl version 1.1, openssl is mostly threadsafe and locking callbacks are no longer used
  // https://stackoverflow.com/questions/60587434/how-crypto-num-locks-will-return-required-number-of-locks

  load_symbol(CRYPTO_THREADID_set_numeric, is_version_1_0);
  load_symbol(CRYPTO_THREADID_set_callback, is_version_1_0);
  load_symbol(CRYPTO_num_locks, is_version_1_0);
  load_symbol(CRYPTO_set_locking_callback, is_version_1_0);

  //libssh2 doesn't support dynamically opening libgit2 so we have to make define each function it uses that it can link against, then resolve the pointers on dlopen.
  // since we dlopen before any calls into libss2 this isn't a problem
  load_symbol(BIO_ctrl, true);
  load_symbol(BIO_free, true);
  load_symbol(BIO_new_file, true);
  load_symbol(BIO_new_mem_buf, true);

  load_symbol(BN_CTX_free, true);
  load_symbol(BN_CTX_new, true);
  load_symbol(BN_bin2bn, true);
  load_symbol(BN_bn2bin, true);
  load_symbol(BN_clear_free, true);
  load_symbol(BN_div, true);
  load_symbol(BN_mod_exp, true);
  load_symbol(BN_new, true);
  load_symbol(BN_num_bits, true);
  load_symbol(BN_rand, true);
  load_symbol(BN_set_word, true);
  load_symbol(BN_sub, true);
  load_symbol(BN_value_one, true);

  load_symbol(DSA_SIG_free, true);
  load_symbol(DSA_SIG_get0, true);
  load_symbol(DSA_SIG_new, true);
  load_symbol(DSA_SIG_set0, true);
  load_symbol(DSA_do_sign, true);
  load_symbol(DSA_do_verify, true);
  load_symbol(DSA_free, true);
  load_symbol(DSA_get0_key, true);
  load_symbol(DSA_get0_pqg, true);
  load_symbol(DSA_new, true);
  load_symbol(DSA_set0_key, true);
  load_symbol(DSA_set0_pqg, true);

  load_symbol(EC_GROUP_get_curve_name, true);
  load_symbol(EC_GROUP_get_degree, true);
  load_symbol(EC_KEY_free, true);
  load_symbol(EC_KEY_generate_key, true);
  load_symbol(EC_KEY_get0_group, true);
  load_symbol(EC_KEY_get0_public_key, true);
  load_symbol(EC_KEY_new_by_curve_name, true);
  load_symbol(EC_KEY_set_private_key, true);
  load_symbol(EC_KEY_set_public_key, true);
  load_symbol(EC_POINT_free, true);
  load_symbol(EC_POINT_new, true);
  load_symbol(EC_POINT_oct2point, true);
  load_symbol(EC_POINT_point2oct, true);

  load_symbol(ECDSA_SIG_free, true);
  load_symbol(ECDSA_SIG_get0, true);
  load_symbol(ECDSA_SIG_new, true);
  load_symbol(ECDSA_SIG_set0, true);
  load_symbol(ECDSA_do_sign, true);
  load_symbol(ECDSA_do_verify, true);

  load_symbol(ECDH_compute_key, true);

  load_symbol(ENGINE_load_builtin_engines, true);
  load_symbol(ENGINE_register_all_complete, true);

  load_symbol(EVP_CIPHER_CTX_free, true);
  load_symbol(EVP_CIPHER_CTX_get_app_data, true);
  load_symbol(EVP_CIPHER_CTX_key_length, true);
  load_symbol(EVP_CIPHER_CTX_new, true);
  load_symbol(EVP_CIPHER_CTX_set_app_data, true);
  load_symbol(EVP_CIPHER_CTX_set_padding, true);
  load_symbol(EVP_CIPHER_meth_free, true);
  load_symbol(EVP_CIPHER_meth_new, true);
  load_symbol(EVP_CIPHER_meth_set_cleanup, true);
  load_symbol(EVP_CIPHER_meth_set_do_cipher, true);
  load_symbol(EVP_CIPHER_meth_set_init, true);
  load_symbol(EVP_CIPHER_meth_set_iv_length, true);

  load_symbol(EVP_Cipher, true);
  load_symbol(EVP_CipherInit, true);
  load_symbol(EVP_DigestFinal, true);
  load_symbol(EVP_DigestInit, true);
  load_symbol(EVP_DigestSign, true);
  load_symbol(EVP_DigestSignInit, true);
  load_symbol(EVP_DigestUpdate, true);
  load_symbol(EVP_DigestVerify, true);
  load_symbol(EVP_DigestVerifyInit, true);
  load_symbol(EVP_EncryptInit, true);
  load_symbol(EVP_EncryptUpdate, true);
  load_symbol(EVP_MD_CTX_free, true);
  load_symbol(EVP_MD_CTX_new, true);
  load_symbol(EVP_PKEY_CTX_free, true);
  load_symbol(EVP_PKEY_CTX_new, true);
  load_symbol(EVP_PKEY_CTX_new_id, true);
  load_symbol(EVP_PKEY_derive, true);
  load_symbol(EVP_PKEY_derive_init, true);
  load_symbol(EVP_PKEY_derive_set_peer, true);
  load_symbol(EVP_PKEY_free, true);
  load_symbol(EVP_PKEY_get1_DSA, true);
  load_symbol(EVP_PKEY_get1_EC_KEY, true);
  load_symbol(EVP_PKEY_get1_RSA, true);
  load_symbol(EVP_PKEY_get_raw_private_key, true);
  load_symbol(EVP_PKEY_get_raw_public_key, true);
  load_symbol(EVP_PKEY_id, true);
  load_symbol(EVP_PKEY_keygen, true);
  load_symbol(EVP_PKEY_keygen_init, true);
  load_symbol(EVP_PKEY_new, true);
  load_symbol(EVP_PKEY_new_raw_private_key, true);
  load_symbol(EVP_PKEY_new_raw_public_key, true);
  load_symbol(EVP_PKEY_set1_DSA, true);
  load_symbol(EVP_PKEY_set1_EC_KEY, true);
  load_symbol(EVP_PKEY_set1_RSA, true);
  load_symbol(EVP_aes_128_cbc, true);
  load_symbol(EVP_aes_128_ecb, true);
  load_symbol(EVP_aes_192_cbc, true);
  load_symbol(EVP_aes_192_ecb, true);
  load_symbol(EVP_aes_256_cbc, true);
  load_symbol(EVP_aes_256_ecb, true);
  load_symbol(EVP_bf_cbc, true);
  load_symbol(EVP_cast5_cbc, true);
  load_symbol(EVP_des_ede3_cbc, true);
  load_symbol(EVP_get_digestbyname, true);
  load_symbol(EVP_md5, true);
  load_symbol(EVP_rc4, true);
  load_symbol(EVP_ripemd160, true);
  load_symbol(EVP_sha1, true);
  load_symbol(EVP_sha256, true);
  load_symbol(EVP_sha512, true);

  load_symbol(HMAC_CTX_free, true);
  load_symbol(HMAC_CTX_new, true);
  load_symbol(HMAC_Final, true);
  load_symbol(HMAC_Init_ex, true);
  load_symbol(HMAC_Update, true);

  load_symbol(PEM_read_bio_DSAPrivateKey, true);
  load_symbol(PEM_read_bio_ECPrivateKey, true);
  load_symbol(PEM_read_bio_PrivateKey, true);
  load_symbol(PEM_read_bio_RSAPrivateKey, true);

  load_symbol(RAND_bytes, true);

  load_symbol(RSA_free, true);
  load_symbol(RSA_get0_factors, true);
  load_symbol(RSA_get0_key, true);
  load_symbol(RSA_new, true);
  load_symbol(RSA_set0_crt_params, true);
  load_symbol(RSA_set0_factors, true);
  load_symbol(RSA_set0_key, true);
  load_symbol(RSA_sign, true);
  load_symbol(RSA_size, true);
  load_symbol(RSA_verify, true);

  return true;
}

bool __linux_should_setup_threading(void) {
  //if these aren't loaded, then we're in a high-enough openssl version that doesn't require thread setup
  return __CRYPTO_THREADID_set_numeric &&
         __CRYPTO_THREADID_set_callback &&
         __CRYPTO_num_locks &&
         __CRYPTO_set_locking_callback;
}

#else
// everything windows or apple specific
#include <openssl/crypto.h>
#endif // __linux__

static uv_mutex_t *opensslMutexes;

void OpenSSL_LockingCallback(int mode, int type, const char *, int) {
  if (mode & CRYPTO_LOCK) {
    uv_mutex_lock(&opensslMutexes[type]);
  } else {
    uv_mutex_unlock(&opensslMutexes[type]);
  }
}

void OpenSSL_IDCallback(CRYPTO_THREADID *id) {
  CRYPTO_THREADID_set_numeric(id, (unsigned long)uv_thread_self());
}

bool init_openssl(void) {
#ifdef __linux__
  return __linux__load_openssl() && __linux_load_symbols();
#else
  return true;
#endif
}

//this should only be called once, ever
void init_openssl_threading(void) {
#ifdef __linux__
  if(!__linux_should_setup_threading()) {
    return;
  }
#endif

  opensslMutexes=(uv_mutex_t *)malloc(CRYPTO_num_locks() * sizeof(uv_mutex_t));

  for (int i=0; i<CRYPTO_num_locks(); i++) {
    uv_mutex_init(&opensslMutexes[i]);
  }

  CRYPTO_set_locking_callback(OpenSSL_LockingCallback);
  CRYPTO_THREADID_set_callback(OpenSSL_IDCallback);
}

bool deinit_openssl(void) {
#ifdef __linux__
  return __linux_unload_openssl();
#else
  return true;
#endif
}
