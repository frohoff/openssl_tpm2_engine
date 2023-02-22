
/*
 * Copyright (C) 2016 James.Bottomley@HansenPartnership.com
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "tpm2-tss.h"
#include "tpm2-common.h"
#include "e_tpm2.h"

char *srk_auth = NULL;
static char *nvprefix = NULL;

static int tpm2_set_nvkey_prefix(char *prefix)
{
	int len;

	if (nvprefix)
		OPENSSL_free(nvprefix);
	len = strlen(prefix);
	nvprefix = OPENSSL_malloc(len+1);
	if (!nvprefix)
		return 0;
	strcpy(nvprefix, prefix);

	return 1;
}

static int tpm2_engine_init(ENGINE * e)
{
	if (!tpm2_set_nvkey_prefix("//nvkey:"))
		return 0;

	if (!tpm2_setup_ecc_methods())
		goto err1;

	if (!tpm2_setup_rsa_methods())
		goto err2;

	return 1;

err2:
	tpm2_teardown_ecc_methods();
err1:
	OPENSSL_free(nvprefix);
	nvprefix = NULL;

	return 0;
}

static int tpm2_engine_finish(ENGINE * e)
{
	tpm2_teardown_ecc_methods();
	tpm2_teardown_rsa_methods();
	OPENSSL_free(nvprefix);
	nvprefix = NULL;

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
		srk_auth = OPENSSL_malloc(len+1);
		strcpy(srk_auth, secret);
	}
	return 1;
}

#define TPM_CMD_PIN ENGINE_CMD_BASE
#define TPM_CMD_NVPREFIX (ENGINE_CMD_BASE+1)

static int tpm2_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ())
{
	switch (cmd) {
		case TPM_CMD_PIN:
			return tpm2_create_srk_policy(p);
		case TPM_CMD_NVPREFIX:
			return tpm2_set_nvkey_prefix(p);
		default:
			break;
	}
	fprintf(stderr, "tpm2: engine command not implemented\n");

	return 0;
}

/* The definitions for control commands specific to this engine */
static const ENGINE_CMD_DEFN tpm2_cmd_defns[] = {
	{TPM_CMD_PIN,
	 "PIN",
	 "Specifies the authorization for the parent primary key (default EmptyAuth)",
	 ENGINE_CMD_FLAG_STRING},
	/* end */
	{TPM_CMD_NVPREFIX,
	 "NVPREFIX",
	 "Specifies the prefix for an NV key (default //nvkey:)",
	 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};

void tpm2_bind_key_to_engine(ENGINE *e, EVP_PKEY *pkey, struct app_data *data)
{
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		tpm2_bind_key_to_engine_rsa(e, pkey, data);
		break;
	case EVP_PKEY_EC:
		tpm2_bind_key_to_engine_ecc(e, pkey, data);
		break;
	default:
		break;
	}
}

static int tpm2_engine_load_nvkey(ENGINE *e, EVP_PKEY **ppkey,
				  TPM_HANDLE key,  UI_METHOD *ui,
				  void *cb_data, int public_only)
{
	TSS_CONTEXT *tssContext;
	TPM_RC rc;
	struct app_data *app_data;
	EVP_PKEY *pkey;
	int askauth = 0;

	if (!ppkey)
		return 1;

	app_data = OPENSSL_malloc(sizeof(*app_data));

	if (!app_data) {
		fprintf(stderr, "Failed to allocate app_data\n");
		return 0;
	}
	memset(app_data, 0, sizeof(*app_data));

	app_data->dir = tpm2_set_unique_tssdir();

	rc = tpm2_create(&tssContext, app_data->dir);
	if (rc)
		goto err;
	key = tpm2_handle_int(tssContext, key);
	rc = tpm2_readpublic(tssContext, key, &app_data->Public.publicArea);
	if (rc)
		goto err_del;
	pkey = tpm2_to_openssl_public(&app_data->Public.publicArea);
	if (!pkey) {
		fprintf(stderr, "Failed to allocate a new EVP_KEY\n");
		goto err_del;
	} else if (public_only) {
		tpm2_delete(app_data);
		goto out;
	}
	app_data->key = tpm2_handle_ext(tssContext, key);

	if (VAL(app_data->Public.publicArea.objectAttributes) & TPMA_OBJECT_NODA) {
		/* no DA implications, try an authorization and see
		 * if NULL is accepted */
		TPM_HANDLE session;

		rc = tpm2_get_bound_handle(tssContext, &session, key, NULL);
		if (rc == TPM_RC_SUCCESS) {
			rc = tpm2_ReadPublic(tssContext, key, NULL, session);
			if (rc)
				tpm2_flush_handle(tssContext, session);
		}
		if (rc != TPM_RC_SUCCESS)
			askauth = 1;
	} else {
		/* assume since we have DA implications, we have a password */
		askauth = 1;
	}

	if (askauth)
		app_data->auth = tpm2_get_auth(ui, "TPM NV Key Password: ", cb_data);

	tpm2_bind_key_to_engine(e, pkey, app_data);

 out:
	*ppkey = pkey;
	TSS_Delete(tssContext);

	return 1;

 err_del:
	TSS_Delete(tssContext);
 err:
	tpm2_delete(app_data);

	return 0;
}

static int tpm2_engine_load_key_core(ENGINE *e, EVP_PKEY **ppkey,
				     const char *key_id, UI_METHOD *ui,
				     void *cb_data, int public_only)
{
	EVP_PKEY *pkey;
	const int nvkey_len = strlen(nvprefix);
	struct app_data *app_data;
	int rc;

	if (!key_id) {
		fprintf(stderr, "key_id is NULL\n");
		return 0;
	}

	if (strncmp(nvprefix, key_id, nvkey_len) == 0) {
		TPM_HANDLE key;

		key = strtoul(key_id + nvkey_len, NULL, 16);
		if ((key >> 24) != TPM_HT_PERSISTENT) {
			fprintf(stderr, "nvkey is not an NV index\n");
			return 0;
		}
		return tpm2_engine_load_nvkey(e, ppkey, key, ui,
					      cb_data, public_only);
	}

	rc = tpm2_load_engine_file(key_id, &app_data, &pkey, ui, cb_data,
				   srk_auth, 1, public_only);
	if (!rc)
		return 0;

	if (!public_only)
		tpm2_bind_key_to_engine(e, pkey, app_data);

	*ppkey = pkey;
	return 1;

}

static EVP_PKEY *tpm2_engine_load_key(ENGINE *e, const char *key_id,
				      UI_METHOD *ui, void *cb)
{
	EVP_PKEY *pkey;
	int ret;

	ret = tpm2_engine_load_key_core(e, &pkey, key_id, ui, cb, 0);
	if (ret == 1)
		return pkey;
	return NULL;
}

static EVP_PKEY *tpm2_engine_load_pubkey(ENGINE *e, const char *key_id,
					 UI_METHOD *ui, void *cb)
{
	EVP_PKEY *pkey;
	int ret;

	ret = tpm2_engine_load_key_core(e, &pkey, key_id, ui, cb, 1);
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
	    !ENGINE_set_load_pubkey_function(e, tpm2_engine_load_pubkey) ||
	    !ENGINE_set_load_privkey_function(e, tpm2_engine_load_key) ||
	    !ENGINE_set_cmd_defns(e, tpm2_cmd_defns))
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

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(tpm2_bind_fn)
