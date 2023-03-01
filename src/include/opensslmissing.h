#ifndef _OPENSSLMISSING_H
#define _OPENSSLMISSING_H

#include <openssl/core.h>
#include <openssl/types.h>
#include <openssl/rsa.h>

struct osslm_sig_ctx {
	EVP_MD *md;
	EVP_MD_CTX *mctx;
	EVP_MD *mgf1;
	int padding;
	int salt_len;
	OSSL_LIB_CTX *libctx;
};

struct osslm_dec_ctx {
	int padding;
	EVP_MD *md;
	EVP_MD *mgfmd;
	unsigned char *label;
	size_t label_size;
	OSSL_LIB_CTX *libctx;
};

int osslm_rsa_digest_to_sign(EVP_MD *md,
			     const unsigned char *digest, int digest_len,
			     unsigned char **to_sign, size_t *to_sign_len);

int bn_b2h_alloc(unsigned char **dst, unsigned char *src, const int len);
void bn_b2h_free(unsigned char *src);
int osslm_rsa_signature_pad(struct osslm_sig_ctx *sctx, unsigned char *padded,
			    int padsize, const unsigned char *from, int fsize);
int osslm_rsa_unpad_oaep(struct osslm_dec_ctx *ctx,
			 unsigned char *to, size_t *tosize,
			 const unsigned char *from, int fromsize);
void osslm_decryption_freectx(struct osslm_dec_ctx *ctx);

int osslm_decryption_set_params(struct osslm_dec_ctx *dctx,
				const OSSL_PARAM params[]);
const OSSL_PARAM *osslm_decryption_settable_params(void *ctx, void *provctx);

int osslm_signature_digest_init(struct osslm_sig_ctx *ctx, const char *mdname,
				const OSSL_PARAM params[]);
int osslm_signature_digest_update(struct osslm_sig_ctx *ctx,
				  const unsigned char *data, size_t datalen);
int osslm_signature_digest_final(struct osslm_sig_ctx *ctx, unsigned char *sig,
				 size_t *siglen, size_t sigsize, int rsa,
				 OSSL_FUNC_signature_sign_fn *ssf, void *sctx);

int osslm_signature_dupctx(struct osslm_sig_ctx *oldctx,
			   struct osslm_sig_ctx *newctx);
void osslm_signature_freectx(struct osslm_sig_ctx *sctx);

int osslm_signature_get_params(struct osslm_sig_ctx *ctx, int ecc,
			       OSSL_PARAM params[]);
int osslm_signature_set_params(struct osslm_sig_ctx *ctx,
			       const OSSL_PARAM params[]);
const OSSL_PARAM *osslm_signature_gettable_params(void *ctx, void *pctx);
const OSSL_PARAM *osslm_signature_settable_params(void *ctx, void *pctx);

#endif
