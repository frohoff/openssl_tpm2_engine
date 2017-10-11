
/*
 * Copyright (C) 2016 James.Bottomley@HansenPartnership.com
 *
 * GPLv2
 *
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssmarshal.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>

#include "tpm2-asn.h"
#include "tpm2-common.h"

#define TPM2_ENGINE_EX_DATA_UNINIT		-1

/* structure pointed to by the RSA object's app_data pointer */
struct app_data
{
	TSS_CONTEXT *tssContext;
	TPM_HANDLE parent;
	TPM_HANDLE key;
	char *auth;
};

static char *srk_auth;

static int tpm2_engine_init(ENGINE * e)
{
	return 1;
}

static int tpm2_engine_finish(ENGINE * e)
{
	return 1;
}

static int tpm2_create_srk_policy(char *secret)
{
	int len;

	if (!secret) {
		OPENSSL_free(srk_auth);
		srk_auth = NULL;
	} else {
		len = strlen(secret);
		srk_auth = OPENSSL_malloc(len);
		strcpy(srk_auth, secret);
	}
	return 1;
}

#define TPM_CMD_PIN ENGINE_CMD_BASE

static int tpm2_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ())
{
	switch (cmd) {
		case TPM_CMD_PIN:
			return tpm2_create_srk_policy(p);
		default:
			break;
	}
	fprintf(stderr, "tpm2: engine command not implemented\n");

	return 0;
}


#ifndef OPENSSL_NO_RSA
/* rsa functions */
static int tpm2_rsa_init(RSA *rsa);
static int tpm2_rsa_finish(RSA *rsa);
static int tpm2_rsa_pub_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_pub_enc(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_priv_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_priv_enc(int, const unsigned char *, unsigned char *, RSA *, int);
//static int tpm2_rsa_sign(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, const RSA *);
#endif

/* The definitions for control commands specific to this engine */
#define TPM2_CMD_PIN		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN tpm2_cmd_defns[] = {
	{TPM2_CMD_PIN,
	 "PIN",
	 "Specifies the secret for the SRK (default is plaintext, else set SECRET_MODE)",
	 ENGINE_CMD_FLAG_STRING},
	/* end */
	{0, NULL, NULL, 0}
};

#ifndef OPENSSL_NO_RSA
static RSA_METHOD tpm2_rsa = {
	"TPM2 RSA method",
	tpm2_rsa_pub_enc,
	tpm2_rsa_pub_dec,
	tpm2_rsa_priv_enc,
	tpm2_rsa_priv_dec,
	NULL, /* set in tpm2_engine_init */
	BN_mod_exp_mont,
	tpm2_rsa_init,
	tpm2_rsa_finish,
	(RSA_FLAG_SIGN_VER | RSA_FLAG_NO_BLINDING),
	NULL,
	NULL, /* sign */
	NULL, /* verify */
	NULL, /* keygen */
};
#endif

static ECDSA_METHOD *tpm2_ecdsa;

/* varibles used to get/set CRYPTO_EX_DATA values */
static int ex_app_data = TPM2_ENGINE_EX_DATA_UNINIT;
static int ec_app_data = TPM2_ENGINE_EX_DATA_UNINIT;

static TPM_HANDLE tpm2_load_key_from_rsa(RSA *rsa, TSS_CONTEXT **tssContext, char **auth)
{
	struct app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);

	if (!app_data)
		return 0;

	*auth = app_data->auth;
	*tssContext = app_data->tssContext;

	return app_data->key;
}

static TPM_HANDLE tpm2_load_key_from_ecc(EC_KEY *eck, TSS_CONTEXT **tssContext, char **auth)
{
	struct app_data *app_data = ECDSA_get_ex_data(eck, ec_app_data);

	if (!app_data) {
		printf("FAILED TO GET APP DATA FROM %p\n", eck);
		return 0;
	}

	*auth = app_data->auth;
	*tssContext = app_data->tssContext;

	return app_data->key;
}

struct tpm_ui {
	UI_METHOD *ui_method;
	pem_password_cb *pem_cb;
};

static char *tpm2_get_auth_ui(UI_METHOD *ui_method, char *prompt, void *cb_data)
{
	UI *ui = UI_new();
	/* Max auth size is name algorithm hash length, so this
	 * is way bigger than necessary */
	char auth[256], *ret = NULL;
	int len;

	if (ui_method)
		UI_set_method(ui, ui_method);

	UI_add_user_data(ui, cb_data);

	if (UI_add_input_string(ui, prompt, UI_INPUT_FLAG_DEFAULT_PWD,
				auth, 0, sizeof(auth)) == 0) {
		fprintf(stderr, "UI_add_input_string failed\n");
		goto out;
	}

	if (UI_process(ui)) {
		fprintf(stderr, "UI_process failed\n");
		goto out;
	}

	len = strlen(auth);
	ret = OPENSSL_malloc(len + 1);
	if (!ret)
		goto out;

	strcpy(ret, auth);

 out:
	UI_free(ui);

	return ret;
}

static char *tpm2_get_auth_pem(pem_password_cb *pem_cb,
				      char *input_string,
				      void *cb_data)
{
	char auth[256], *ret;
	int len;

	EVP_set_pw_prompt(input_string);
	if (!pem_cb)
		pem_cb = PEM_def_callback;
	pem_cb(auth, sizeof(auth), 0, cb_data);
	EVP_set_pw_prompt(NULL);

	len = strlen(auth);
	ret = OPENSSL_malloc(len + 1);
	if (!ret)
		goto out;

	strcpy(ret, auth);

 out:
	return ret;
}

static char *tpm2_get_auth(struct tpm_ui *ui, char *input_string,
			   void *cb_data)
{
	if (ui->ui_method)
		return tpm2_get_auth_ui(ui->ui_method, input_string, cb_data);
	else
		return tpm2_get_auth_pem(ui->pem_cb, input_string, cb_data);
}

void tpm2_bind_key_to_engine_rsa(EVP_PKEY *pkey, void *data)
{
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);

	rsa->meth = &tpm2_rsa;
	/* call our local init function here */
	rsa->meth->init(rsa);

	RSA_set_ex_data(rsa, ex_app_data, data);

	/* release the reference EVP_PKEY_get1_RSA obtained */
	RSA_free(rsa);
}

void tpm2_bind_key_to_engine_ecc(EVP_PKEY *pkey, void *data)
{
	EC_KEY *eck = EVP_PKEY_get1_EC_KEY(pkey);

	if (!ECDSA_set_ex_data(eck, ec_app_data, data))
		fprintf(stderr, "Failed to bind key to engine (ecc ex_data)\n");
	else
		ECDSA_set_method(eck, tpm2_ecdsa);

	EC_KEY_free(eck);
}

void tpm2_bind_key_to_engine(EVP_PKEY *pkey, void *data)
{
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		tpm2_bind_key_to_engine_rsa(pkey, data);
		break;
	case EVP_PKEY_EC:
		tpm2_bind_key_to_engine_ecc(pkey, data);
		break;
	default:
		break;
	}
}

static int tpm2_engine_load_key_core(ENGINE *e, EVP_PKEY **ppkey,
				     const char *key_id,  BIO *bio,
				     struct tpm_ui *ui, void *cb_data)
{
	Load_In in;
	Load_Out out;
	TSS_CONTEXT *tssContext;
	TPM_RC rc;
	EVP_PKEY *pkey;
	BIO *bf;
	TSSLOADABLE *tssl;
	BYTE *buffer;
	INT32 size;
	struct app_data *app_data;
	char oid[128];
	int empty_auth;

	if (!key_id && !bio) {
		fprintf(stderr, "key_id or bio is NULL\n");
		return 0;
	}

	if (bio)
		bf = bio;
	else
		bf = BIO_new_file(key_id, "r");
	if (!bf) {
		fprintf(stderr, "File %s does not exist or cannot be read\n", key_id); 
		return 0;
	}

	tssl = PEM_read_bio_TSSLOADABLE(bf, NULL, NULL, NULL);

	if (!bio)
		BIO_free(bf);

	if (!tssl) {
		if (ppkey)
			fprintf(stderr, "Failed to parse file %s\n", key_id);
		return 0;
	}

	if (!ppkey) {
		TSSLOADABLE_free(tssl);
		return 1;
	}

	if (OBJ_obj2txt(oid, sizeof(oid), tssl->type, 1) == 0) {
		fprintf(stderr, "Failed to parse object type\n");
		goto err;
	}

	if (strcmp(OID_loadableKey, oid) == 0) {
		;
	} else if (strcmp(OID_12Key, oid) == 0) {
		fprintf(stderr, "TPM1.2 key is not importable by TPM2.0\n");
		goto err;
	} else if (strcmp(OID_importableKey, oid) == 0) {
		fprintf(stderr, "Importable keys currently unsupported\n");
		goto err;
	} else {
		fprintf(stderr, "Unrecognised object type\n");
		goto err;
	}

	app_data = OPENSSL_malloc(sizeof(struct app_data));

	if (!app_data) {
		fprintf(stderr, "Failed to allocate app_data\n");
		goto err;
	}

	rc = TSS_Create(&tssContext);
	if (rc) {
		tpm2_error(rc, "TSS_Create");
		goto err_free;
	}
	app_data->tssContext = tssContext;

	app_data->parent = 0;
	if (tssl->parent)
		app_data->parent = ASN1_INTEGER_get(tssl->parent);

	if (app_data->parent)
		in.parentHandle = app_data->parent;
	else
		tpm2_load_srk(tssContext, &in.parentHandle, srk_auth, NULL);

	empty_auth = tssl->emptyAuth;

	buffer = tssl->privkey->data;
	size = tssl->privkey->length;
	TPM2B_PRIVATE_Unmarshal(&in.inPrivate, &buffer, &size);
	buffer = tssl->pubkey->data;
	size = tssl->pubkey->length;
	TPM2B_PUBLIC_Unmarshal(&in.inPublic, &buffer, &size, FALSE);

	/* create the new objects to return */
	pkey = tpm2_to_openssl_public(&in.inPublic.publicArea);
	if (!pkey) {
		fprintf(stderr, "Failed to allocate a new EVP_KEY\n");
		goto err_free_del;
	}

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0,
			 TPM_RH_NULL, NULL, 0);

	if (rc) {
		tpm2_error(rc, "TPM2_Load");
		goto err_free_key;
	}

	app_data->key = out.objectHandle;

	app_data->auth = NULL;
	if (empty_auth == 0) {
		app_data->auth = tpm2_get_auth(ui, "TPM Key Password: ", cb_data);
		if (!app_data->auth)
			goto err_unload;
	}

	TSSLOADABLE_free(tssl);

	tpm2_bind_key_to_engine(pkey, app_data);

	*ppkey = pkey;
	return 1;

 err_unload:
	tpm2_flush_handle(tssContext, app_data->key);
 err_free_key:
	EVP_PKEY_free(pkey);
 err_free_del:
	TSS_Delete(tssContext);
 err_free:
	OPENSSL_free(app_data);
	tpm2_flush_srk(tssContext);
 err:
	TSSLOADABLE_free(tssl);

	return 0;
}

static void tpm2_ecdsa_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			   int idx, long argl, void *argp)
{
	struct app_data *data = ptr;

	if (!data)
		return;

	tpm2_flush_handle(data->tssContext, data->key);
	if (data->parent == 0)
		tpm2_flush_srk(data->tssContext);

	TSS_Delete(data->tssContext);

	OPENSSL_free(data);
}

static ECDSA_SIG *tpm2_ecdsa_sign(const unsigned char *dgst, int dgst_len,
				  const BIGNUM *kinv, const BIGNUM *rp,
				  EC_KEY *eck)
{
	TPM_RC rc;
	Sign_In in;
	Sign_Out out;
	TSS_CONTEXT *tssContext;
	char *auth;
	TPM_HANDLE authHandle;
	ECDSA_SIG *sig;

	/* The TPM insists on knowing the digest type, so
	 * calculate that from the size */
	switch (dgst_len) {
	case SHA_DIGEST_LENGTH:
		in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA1;
		break;
	case SHA256_DIGEST_LENGTH:
		in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
		break;
	case SHA384_DIGEST_LENGTH:
		in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA384;
		break;
#ifdef TPM_ALG_SHA512
	case SHA512_DIGEST_LENGTH:
		in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA512;
		break;
#endif
	default:
		printf("ECDSA signature: Unknown digest length, cannot deduce hash type for TPM\n");
		return NULL;
	}

	in.keyHandle = tpm2_load_key_from_ecc(eck, &tssContext, &auth);
	if (in.keyHandle == 0) {
		fprintf(stderr, "Failed to get Key Handle in TPM EC key routines\n");
		return NULL;
	}

	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.digest.t.size = dgst_len;
	memcpy(in.digest.t.buffer, dgst, dgst_len);
	in.validation.tag = TPM_ST_HASHCHECK;
	in.validation.hierarchy = TPM_RH_NULL;
	in.validation.digest.t.size = 0;
	rc = tpm2_get_hmac_handle(tssContext, &authHandle, 0);
	if (rc)
		return NULL;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Sign,
			 authHandle, auth, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_Sign");
		tpm2_flush_handle(tssContext, authHandle);
		return NULL;
	}

	sig = ECDSA_SIG_new();
	if (!sig)
		return NULL;

	sig->r = BN_bin2bn(out.signature.signature.ecdsa.signatureR.t.buffer,
			   out.signature.signature.ecdsa.signatureR.t.size,
			   NULL);
	sig->s = BN_bin2bn(out.signature.signature.ecdsa.signatureS.t.buffer,
			   out.signature.signature.ecdsa.signatureS.t.size,
			   NULL);

	return sig;
}

static EVP_PKEY *tpm2_engine_load_key(ENGINE *e, const char *key_id,
				      UI_METHOD *ui, void *cb)
{
	struct tpm_ui tui = {
		.ui_method = ui,
		.pem_cb = NULL,
	};
	EVP_PKEY *pkey;
	int ret;

	ret = tpm2_engine_load_key_core(e, &pkey, key_id, NULL, &tui, cb);
	if (ret == 1)
		return pkey;
	return NULL;
}

/* Constants used when creating the ENGINE */
static const char *engine_tpm2_id = "tpm2";
static const char *engine_tpm2_name = "TPM2 hardware engine support";

static int tpm2_setup_ecdsa_methods(void)
{
	tpm2_ecdsa = ECDSA_METHOD_new(NULL);

	if (!tpm2_ecdsa)
		return 0;

	ECDSA_METHOD_set_name(tpm2_ecdsa, (char *)engine_tpm2_name);
	ECDSA_METHOD_set_sign(tpm2_ecdsa, tpm2_ecdsa_sign);

	ec_app_data =  ECDSA_get_ex_new_index(0, NULL, NULL, NULL, tpm2_ecdsa_free);

	return 1;
}

/* This internal function is used by ENGINE_tpm() and possibly by the
 * "dynamic" ENGINE support too */
static int tpm2_bind_helper(ENGINE * e)
{
	if (!ENGINE_set_id(e, engine_tpm2_id) ||
	    !ENGINE_set_name(e, engine_tpm2_name) ||
#ifndef OPENSSL_NO_RSA
	    !ENGINE_set_RSA(e, &tpm2_rsa) ||
#endif
	    !ENGINE_set_init_function(e, tpm2_engine_init) ||
	    !ENGINE_set_finish_function(e, tpm2_engine_finish) ||
	    !ENGINE_set_ctrl_function(e, tpm2_engine_ctrl) ||
	    !ENGINE_set_load_pubkey_function(e, tpm2_engine_load_key) ||
	    !ENGINE_set_load_privkey_function(e, tpm2_engine_load_key) ||
	    !ENGINE_set_cmd_defns(e, tpm2_cmd_defns) ||
	    !tpm2_setup_ecdsa_methods() ||
	    !ENGINE_set_ECDSA(e, tpm2_ecdsa))
		return 0;

	return 1;
}


#ifndef OPENSSL_NO_RSA
static int tpm2_rsa_init(RSA *rsa)
{
	if (ex_app_data == TPM2_ENGINE_EX_DATA_UNINIT)
		ex_app_data = RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);

	if (ex_app_data == TPM2_ENGINE_EX_DATA_UNINIT) {
		fprintf(stderr, "Failed to get memory for external data\n");
		return 0;
	}

	return 1;
}

static int tpm2_rsa_finish(RSA *rsa)
{
	struct app_data *app_data = RSA_get_ex_data(rsa, ex_app_data);
	TSS_CONTEXT *tssContext;

	if (!app_data)
		return 1;

	tssContext = app_data->tssContext;

	tpm2_flush_handle(tssContext, app_data->key);
	if (app_data->parent == 0)
		tpm2_flush_srk(tssContext);

	OPENSSL_free(app_data);

	TSS_Delete(tssContext);

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

	in.keyHandle = tpm2_load_key_from_rsa(rsa, &tssContext, &auth);

	if (in.keyHandle == 0) {
		rv = RSA_PKCS1_SSLeay()->rsa_priv_dec(flen, from, to, rsa,
						      padding);
		if (rv < 0)
			fprintf(stderr, "rsa_priv_dec failed\n");

		return rv;
	}

	rv = -1;
	if (padding != RSA_PKCS1_PADDING) {
		fprintf(stderr, "Non PKCS1 padding asked for\n");
		return rv;
	}

	in.inScheme.scheme = TPM_ALG_RSAES;
	in.cipherText.t.size = flen;
	memcpy(in.cipherText.t.buffer, from, flen);
	in.label.t.size = 0;

	rc = tpm2_get_hmac_handle(tssContext, &authHandle, 0);
	if (rc)
		return rv;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_RSA_Decrypt,
			 authHandle, auth, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_RSA_Decrypt");
		/* failure means auth handle is not flushed */
		tpm2_flush_handle(tssContext, authHandle);
		return rv;
	}
 
	memcpy(to, out.message.t.buffer,
	       out.message.t.size);

	rv = out.message.t.size;

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

	in.keyHandle = tpm2_load_key_from_rsa(rsa, &tssContext, &auth);

	if (in.keyHandle == 0) {
		rv = RSA_PKCS1_SSLeay()->rsa_priv_enc(flen, from, to, rsa,
						      padding);
		if (rv < 0)
			fprintf(stderr, "pass through signing failed\n");

		return rv;
	}

	rv = -1;
	if (padding != RSA_PKCS1_PADDING) {
		fprintf(stderr, "Non PKCS1 padding asked for\n");
		return rv;
	}

	rc = tpm2_get_hmac_handle(tssContext, &authHandle, 0);
	if (rc)
		return rv;

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
			 authHandle, auth, 0,
			 TPM_RH_NULL, NULL, 0);

	if (rc) {
		tpm2_error(rc, "TPM2_RSA_Decrypt");
		/* failure means auth handle is not flushed */
		tpm2_flush_handle(tssContext, authHandle);
		return rv;
	}

	memcpy(to, out.message.t.buffer,
	       out.message.t.size);

	rv = out.message.t.size;

	return rv;
}

#endif

/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
static int tpm2_bind_fn(ENGINE * e, const char *id)
{
	if (id && (strcmp(id, engine_tpm2_id) != 0)) {
		fprintf(stderr, "Called for id %s != my id %s\n",
		       id, engine_tpm2_id);
		return 0;
	}
	if (!tpm2_bind_helper(e)) {
		fprintf(stderr, "tpm2_bind_helper failed\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(tpm2_bind_fn)
