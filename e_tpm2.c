
/*
 * Copyright (C) 2016 James.Bottomley@HansenPartnership.com
 *
 * GPLv2
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssmarshal.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>

#include "tpm2-asn.h"
#include "tpm2-common.h"
#include "e_tpm2.h"

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
	EVP_PKEY *pkey;
	TPM2B_PUBLIC p;
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

	app_data = OPENSSL_malloc(sizeof(*app_data));

	if (!app_data) {
		fprintf(stderr, "Failed to allocate app_data\n");
		goto err;
	}
	memset(app_data, 0, sizeof(*app_data));

	app_data->dir = tpm2_set_unique_tssdir();

	if (tssl->parent)
		app_data->parent = ASN1_INTEGER_get(tssl->parent);
	else
		/* older keys have absent parent */
		app_data->parent = TPM_RH_OWNER;

	empty_auth = tssl->emptyAuth;

	app_data->priv = OPENSSL_malloc(tssl->privkey->length);
	if (!app_data->priv)
		goto err_free;
	app_data->priv_len = tssl->privkey->length;
	memcpy(app_data->priv, tssl->privkey->data, app_data->priv_len);

	app_data->pub = OPENSSL_malloc(tssl->pubkey->length);
	if (!app_data->pub)
		goto err_free;
	app_data->pub_len = tssl->pubkey->length;
	memcpy(app_data->pub, tssl->pubkey->data, app_data->pub_len);
	buffer = app_data->pub;
	size = app_data->pub_len;
	TPM2B_PUBLIC_Unmarshal(&p, &buffer, &size, FALSE);
	/* create the new objects to return */
	pkey = tpm2_to_openssl_public(&p.publicArea);
	if (!pkey) {
		fprintf(stderr, "Failed to allocate a new EVP_KEY\n");
		goto err_free;
	}

	if (empty_auth == 0) {
		app_data->auth = tpm2_get_auth(ui, "TPM Key Password: ", cb_data);
		if (!app_data->auth)
			goto err_free_key;
	}

	TSSLOADABLE_free(tssl);

	tpm2_bind_key_to_engine(pkey, app_data);

	*ppkey = pkey;
	return 1;

 err_free_key:
	EVP_PKEY_free(pkey);
 err_free:
	tpm2_delete(app_data);
 err:
	TSSLOADABLE_free(tssl);

	return 0;
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

/* This internal function is used by ENGINE_tpm() and possibly by the
 * "dynamic" ENGINE support too */
static int tpm2_bind_helper(ENGINE * e)
{
	if (!ENGINE_set_id(e, engine_tpm2_id) ||
	    !ENGINE_set_name(e, engine_tpm2_name) ||
	    !ENGINE_set_init_function(e, tpm2_engine_init) ||
	    !ENGINE_set_finish_function(e, tpm2_engine_finish) ||
	    !ENGINE_set_ctrl_function(e, tpm2_engine_ctrl) ||
	    !ENGINE_set_load_pubkey_function(e, tpm2_engine_load_key) ||
	    !ENGINE_set_load_privkey_function(e, tpm2_engine_load_key) ||
	    !ENGINE_set_cmd_defns(e, tpm2_cmd_defns) ||
	    !tpm2_setup_ecc_methods() ||
	    !tpm2_setup_rsa_methods())
		return 0;

	return 1;
}


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

TPM_HANDLE tpm2_load_key(TSS_CONTEXT **tsscp, struct app_data *app_data)
{
	TSS_CONTEXT *tssContext;
	Load_In in;
	Load_Out out;
	TPM_HANDLE key = 0;
	TPM_RC rc;
	BYTE *buffer;
	INT32 size;

	rc = tpm2_create(&tssContext, app_data->dir);
	if (rc)
		return 0;

	buffer = app_data->priv;
	size = app_data->priv_len;
	TPM2B_PRIVATE_Unmarshal(&in.inPrivate, &buffer, &size);

	buffer = app_data->pub;
	size = app_data->pub_len;
	TPM2B_PUBLIC_Unmarshal(&in.inPublic, &buffer, &size, FALSE);

	if ((app_data->parent & 0xff000000) == 0x81000000) {
		in.parentHandle = app_data->parent;
	} else {
		rc = tpm2_load_srk(tssContext, &in.parentHandle, NULL, NULL, app_data->parent);
		if (rc)
			goto out;
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		tpm2_error(rc, "TPM2_Load");
	else
		key = out.objectHandle;

	tpm2_flush_srk(tssContext, in.parentHandle);
 out:
	if (!key)
		TSS_Delete(tssContext);
	else
		*tsscp = tssContext;
	return key;
}

void tpm2_unload_key(TSS_CONTEXT *tssContext, TPM_HANDLE key)
{
	tpm2_flush_handle(tssContext, key);

	TSS_Delete(tssContext);
}

void tpm2_delete(struct app_data *app_data)
{
	OPENSSL_free(app_data->priv);
	OPENSSL_free(app_data->pub);

	if (rmdir(app_data->dir) < 0)
		perror("Unlinking TPM_DATA_DIR");

	OPENSSL_free((void *)app_data->dir);

	OPENSSL_free(app_data);
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(tpm2_bind_fn)
