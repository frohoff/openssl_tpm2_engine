/*
 * Copyright (C) 2017 James.Bottomley@HansenPartnership.com
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define TSSINCLUDE(x) < TSS_INCLUDE/x >
#include TSSINCLUDE(tss.h)
#include TSSINCLUDE(tssutils.h)
#include TSSINCLUDE(tssmarshal.h)
#include TSSINCLUDE(tssresponsecode.h)
#include TSSINCLUDE(Unmarshal_fp.h)

#include "tpm2-common.h"
#include "e_tpm2.h"


/* varibles used to get/set CRYPTO_EX_DATA values */
static int ex_app_data = TPM2_ENGINE_EX_DATA_UNINIT;

RSA_METHOD *tpm2_rsa;

#if OPENSSL_VERSION_NUMBER < 0x10100000
/* rsa functions */
static int tpm2_rsa_init(RSA *rsa);
static int tpm2_rsa_pub_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_pub_enc(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_priv_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_priv_enc(int, const unsigned char *, unsigned char *, RSA *, int);
//static int tpm2_rsa_sign(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, const RSA *);

static RSA_METHOD tpm2_rsa_meths = {
	"TPM2 RSA method",
	tpm2_rsa_pub_enc,
	tpm2_rsa_pub_dec,
	tpm2_rsa_priv_enc,
	tpm2_rsa_priv_dec,
	NULL, /* set in tpm2_engine_init */
	BN_mod_exp_mont,
	tpm2_rsa_init,
	NULL,
	(RSA_FLAG_SIGN_VER | RSA_FLAG_NO_BLINDING),
	NULL,
	NULL, /* sign */
	NULL, /* verify */
	NULL, /* keygen */
};

static int tpm2_rsa_init(RSA *rsa)
{
	return 1;
}

static int tpm2_rsa_pub_dec(int flen,
			   const unsigned char *from,
			   unsigned char *to,
			   RSA *rsa,
			   int padding)
{
	int rv;

	rv = RSA_PKCS1_SSLeay()->rsa_pub_dec(flen, from, to, rsa,
					     padding);
	if (rv < 0) {
		fprintf(stderr, "rsa_pub_dec failed\n");
		return 0;
	}

	return rv;
}

static int tpm2_rsa_pub_enc(int flen,
			   const unsigned char *from,
			   unsigned char *to,
			   RSA *rsa,
			   int padding)
{
	int rv;

	rv = RSA_PKCS1_SSLeay()->rsa_pub_enc(flen, from, to, rsa,
					     padding);
	if (rv < 0)
		fprintf(stderr, "rsa_pub_enc failed\n");

	return rv;
}

#endif

static TPM_HANDLE tpm2_load_key_from_rsa(RSA *rsa, TSS_CONTEXT **tssContext,
					 char **auth, TPM_SE *sessionType,
					 int *num_commands,
					 struct policy_command **commands,
					 TPM_ALG_ID *nameAlg)
{
	struct app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);

	if (!app_data)
		return 0;

	*auth = app_data->auth;
	*sessionType = app_data->req_policy_session ?
		       TPM_SE_POLICY : TPM_SE_HMAC;
	*commands = app_data->commands;
	*num_commands = app_data->num_commands;
	*nameAlg = app_data->name_alg;

	return tpm2_load_key(tssContext, app_data);
}

void tpm2_bind_key_to_engine_rsa(EVP_PKEY *pkey, void *data)
{
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	rsa->meth = tpm2_rsa;
	/* call our local init function here */
	rsa->meth->init(rsa);
#else
	RSA_set_method(rsa, tpm2_rsa);
#endif

	RSA_set_ex_data(rsa, ex_app_data, data);

	/* release the reference EVP_PKEY_get1_RSA obtained */
	RSA_free(rsa);
}

static void tpm2_rsa_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			  int idx, long argl, void *argp)
{
	struct app_data *app_data = ptr;

	if (!app_data)
		return;

	tpm2_delete(app_data);
}

static int tpm2_rsa_priv_dec(int flen,
			    const unsigned char *from,
			    unsigned char *to,
			    RSA *rsa,
			    int padding)
{
	TPM_RC rc;
	int rv;
	RSA_Decrypt_In in;
	RSA_Decrypt_Out out;
	TSS_CONTEXT *tssContext;
	char *auth;
	TPM_HANDLE authHandle;
	TPM_SE sessionType;
	int num_commands;
	struct policy_command *commands;
	TPM_ALG_ID nameAlg;

	in.keyHandle = tpm2_load_key_from_rsa(rsa, &tssContext, &auth,
					      &sessionType, &num_commands,
					      &commands, &nameAlg);

	if (in.keyHandle == 0) {
		fprintf(stderr, "Failed to get Key Handle in TPM RSA key routines\n");

		return -1;
	}

	rv = -1;
	if (padding != RSA_PKCS1_PADDING) {
		fprintf(stderr, "Non PKCS1 padding asked for\n");
		goto out;
	}

	in.inScheme.scheme = TPM_ALG_RSAES;
	in.cipherText.t.size = flen;
	memcpy(in.cipherText.t.buffer, from, flen);
	in.label.t.size = 0;

	rc = tpm2_get_session_handle(tssContext, &authHandle, 0, sessionType,
				     nameAlg);
	if (rc)
		goto out;

	if (sessionType == TPM_SE_POLICY) {
		rc = tpm2_init_session(tssContext, authHandle,
				       num_commands, commands, nameAlg);
		if (rc)
			goto out;
	}

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_RSA_Decrypt,
			 authHandle, auth, TPMA_SESSION_ENCRYPT,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_RSA_Decrypt");
		/* failure means auth handle is not flushed */
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}
 
	memcpy(to, out.message.t.buffer,
	       out.message.t.size);

	rv = out.message.t.size;
 out:
	tpm2_unload_key(tssContext, in.keyHandle);
	return rv;
}

static int tpm2_rsa_priv_enc(int flen,
			    const unsigned char *from,
			    unsigned char *to,
			    RSA *rsa,
			    int padding)
{
	TPM_RC rc;
	int rv, size;
	RSA_Decrypt_In in;
	RSA_Decrypt_Out out;
	TSS_CONTEXT *tssContext;
	char *auth;
	TPM_HANDLE authHandle;
	TPM_SE sessionType;
	int num_commands;
	struct policy_command *commands;
	TPM_ALG_ID nameAlg;

	if (padding != RSA_PKCS1_PADDING) {
		fprintf(stderr, "Non PKCS1 padding asked for\n");
		return -1;
	}

	in.keyHandle = tpm2_load_key_from_rsa(rsa, &tssContext, &auth,
					      &sessionType, &num_commands,
					      &commands, &nameAlg);

	if (in.keyHandle == 0) {
		fprintf(stderr, "Failed to get Key Handle in TPM RSA routines\n");

		return -1;
	}

	rv = -1;
	rc = tpm2_get_session_handle(tssContext, &authHandle, 0, sessionType,
				     nameAlg);
	if (rc)
		goto out;

	if (sessionType == TPM_SE_POLICY) {
		rc = tpm2_init_session(tssContext, authHandle,
				       num_commands, commands, nameAlg);
		if (rc)
			goto out;
	}

	/* this is slightly paradoxical that we're doing a Decrypt
	 * operation: the only material difference between decrypt and
	 * encrypt is where the padding is applied or checked, so if
	 * you apply your own padding up to the RSA block size and use
	 * TPM_ALG_NULL, which means no padding check, a decrypt
	 * operation effectively becomes an encrypt */
	size = RSA_size(rsa);
	in.inScheme.scheme = TPM_ALG_NULL;
	in.cipherText.t.size = size;
	RSA_padding_add_PKCS1_type_1(in.cipherText.t.buffer, size, from, flen);
	in.label.t.size = 0;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_RSA_Decrypt,
			 authHandle, auth, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);

	if (rc) {
		tpm2_error(rc, "TPM2_RSA_Decrypt");
		/* failure means auth handle is not flushed */
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}

	memcpy(to, out.message.t.buffer,
	       out.message.t.size);

	rv = out.message.t.size;

 out:
	tpm2_unload_key(tssContext, in.keyHandle);

	return rv;
}

int tpm2_setup_rsa_methods(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	tpm2_rsa = &tpm2_rsa_meths;
#else
	tpm2_rsa = RSA_meth_dup(RSA_PKCS1_OpenSSL());
	RSA_meth_set1_name(tpm2_rsa, "tpm2 rsa");
	RSA_meth_set_priv_enc(tpm2_rsa, tpm2_rsa_priv_enc);
	RSA_meth_set_priv_dec(tpm2_rsa, tpm2_rsa_priv_dec);
#endif

	ex_app_data = RSA_get_ex_new_index(0, NULL, NULL, NULL, tpm2_rsa_free);

	return 1;
}
