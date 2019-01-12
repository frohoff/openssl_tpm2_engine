
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

#define TSSINCLUDE(x) < TSS_INCLUDE/x >
#include TSSINCLUDE(tss.h)
#include TSSINCLUDE(tssutils.h)
#include TSSINCLUDE(tssmarshal.h)
#include TSSINCLUDE(tssresponsecode.h)
#include TSSINCLUDE(Unmarshal_fp.h)

#include "tpm2-asn.h"
#include "tpm2-common.h"
#include "e_tpm2.h"

static char *srk_auth;
static char *nvprefix;

static int tpm2_engine_init(ENGINE * e)
{
	return 1;
}

static int tpm2_engine_finish(ENGINE * e)
{
	return 1;
}

static int tpm2_set_nvkey_prefix(char *prefix)
{
	int len;

	if (nvprefix)
		OPENSSL_free(nvprefix);
	len = strlen(prefix);
	nvprefix = OPENSSL_malloc(len+1);
	strcpy(nvprefix, prefix);

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

static int tpm2_engine_load_nvkey(ENGINE *e, EVP_PKEY **ppkey,
				  TPM_HANDLE key,  BIO *bio,
				  struct tpm_ui *ui, void *cb_data)
{
	TPMT_PUBLIC p;
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
	rc = tpm2_readpublic(tssContext, key, &p);
	if (rc)
		goto err_del;
	app_data->name_alg = p.nameAlg;
	pkey = tpm2_to_openssl_public(&p);
	if (!pkey) {
		fprintf(stderr, "Failed to allocate a new EVP_KEY\n");
		goto err_del;
	}
	app_data->key = key;

	if (p.objectAttributes.val & TPMA_OBJECT_NODA) {
		/* no DA implications, try an authorization and see
		 * if NULL is accepted */
		ReadPublic_In rin;
		ReadPublic_Out rout;
		TPM_HANDLE session;

		rin.objectHandle = key;
		rc = tpm2_get_bound_handle(tssContext, &session, key, NULL);
		if (rc == TPM_RC_SUCCESS) {
			rc = TSS_Execute(tssContext,
					 (RESPONSE_PARAMETERS *)&rout,
					 (COMMAND_PARAMETERS *)&rin,
					 NULL,
					 TPM_CC_ReadPublic,
					 session, NULL, TPMA_SESSION_ENCRYPT,
					 TPM_RH_NULL, NULL, 0);
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

	tpm2_bind_key_to_engine(pkey, app_data);

	*ppkey = pkey;
	TSS_Delete(tssContext);

	return 1;

 err_del:
	TSS_Delete(tssContext);
 err:
	tpm2_delete(app_data);

	return 0;
}

static int tpm2_engine_load_key_policy(struct app_data *app_data,
				       STACK_OF(TSSOPTPOLICY) *st_policy)
{
	struct policy_command *command;
	TSSOPTPOLICY *policy;
	int i, commands_len;

	app_data->num_commands = sk_TSSOPTPOLICY_num(st_policy);
	if (app_data->num_commands <= 0)
		return 1;

	commands_len = sizeof(struct policy_command) * app_data->num_commands;
	app_data->commands = OPENSSL_malloc(commands_len);
	if (!app_data->commands)
		return 0;

	for (i = 0; i < app_data->num_commands; i++) {
		policy = sk_TSSOPTPOLICY_value(st_policy, i);
		if (!policy)
			return 0;

		command = app_data->commands + i;
		command->code = ASN1_INTEGER_get(policy->CommandCode);
		command->size = policy->CommandPolicy->length;
		command->policy = NULL;

		if (!command->size)
			continue;

		command->policy = OPENSSL_malloc(command->size);
		if (!command->policy)
			return 0;

		memcpy(command->policy, policy->CommandPolicy->data,
		       command->size);
	}

	return 1;
}

static int tpm2_engine_load_key_core(ENGINE *e, EVP_PKEY **ppkey,
				     const char *key_id,  BIO *bio,
				     struct tpm_ui *ui, void *cb_data)
{
	EVP_PKEY *pkey;
	BIO *bf;
	TSSLOADABLE *tssl = NULL;
	TSSPRIVKEY *tpk = NULL;
	BYTE *buffer;
	INT32 size;
	struct app_data *app_data;
	char oid[128];
	int empty_auth, version = 0;
	const int nvkey_len = strlen(nvprefix);
	ASN1_OBJECT *type;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	STACK_OF(TSSOPTPOLICY) *policy;
	ASN1_OCTET_STRING *privkey;
	ASN1_OCTET_STRING *secret = NULL;
	Import_In iin;

	if (!key_id && !bio) {
		fprintf(stderr, "key_id or bio is NULL\n");
		return 0;
	}

	if (strncmp(nvprefix, key_id, nvkey_len) == 0) {
		TPM_HANDLE key;

		key = strtoul(key_id + nvkey_len, NULL, 16);
		if ((key & 0xff000000) != 0x81000000) {
			fprintf(stderr, "nvkey is not an NV index\n");
			return 0;
		}
		return tpm2_engine_load_nvkey(e, ppkey, key, bio,
					      ui, cb_data);
	}

	if (bio)
		bf = bio;
	else
		bf = BIO_new_file(key_id, "r");
	if (!bf) {
		fprintf(stderr, "File %s does not exist or cannot be read\n", key_id); 
		return 0;
	}

	tpk = PEM_read_bio_TSSPRIVKEY(bf, NULL, NULL, NULL);
	if (tpk) {
		version = 1;
		type = tpk->type;
		empty_auth = tpk->emptyAuth;
		parent = tpk->parent;
		pubkey = tpk->pubkey;
		privkey = tpk->privkey;
		policy = tpk->policy;
		secret = tpk->secret;
	} else {
		BIO_seek(bf, 0);
		tssl = PEM_read_bio_TSSLOADABLE(bf, NULL, NULL, NULL);
		if (tssl) {
			/* have error from failed TSSPRIVKEY load */
			ERR_clear_error();
			type = tssl->type;
			empty_auth = tssl->emptyAuth;
			parent = tssl->parent;
			pubkey = tssl->pubkey;
			privkey = tssl->privkey;
			policy = tssl->policy;
		}
	}

	if (!bio)
		BIO_free(bf);

	if (!tssl && !tpk) {
		if (ppkey)
			fprintf(stderr, "Failed to parse file %s\n", key_id);
		return 0;
	}

	if (!ppkey) {
		TSSLOADABLE_free(tssl);
		TSSPRIVKEY_free(tpk);
		return 1;
	}

	if (OBJ_obj2txt(oid, sizeof(oid), type, 1) == 0) {
		fprintf(stderr, "Failed to parse object type\n");
		goto err;
	}

	if (strcmp(OID_loadableKey, oid) == 0) {
		if (version != 1) {
			fprintf(stderr, "New type found in old format key\n");
			goto err;
		}
	} else if (strcmp(OID_OldloadableKey, oid) == 0) {
		if (version != 0) {
			fprintf(stderr, "Old type found in new format key\n");
			goto err;
		}
	} else if (strcmp(OID_importableKey, oid) == 0) {
		if (!secret) {
			fprintf(stderr, "Importable keys require an encrypted secret\n");
			goto err;
		}
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

	app_data->version = version;
	app_data->dir = tpm2_set_unique_tssdir();

	if (parent)
		app_data->parent = ASN1_INTEGER_get(parent);
	else
		/* older keys have absent parent */
		app_data->parent = TPM_RH_OWNER;

	app_data->pub = OPENSSL_malloc(pubkey->length);
	if (!app_data->pub)
		goto err_free;
	app_data->pub_len = pubkey->length;
	memcpy(app_data->pub, pubkey->data, app_data->pub_len);

	buffer = app_data->pub;
	size = app_data->pub_len;
	TPM2B_PUBLIC_Unmarshal(&iin.objectPublic, &buffer, &size, FALSE);
	app_data->name_alg = iin.objectPublic.publicArea.nameAlg;

	if (strcmp(OID_importableKey, oid) == 0) {
		TPM_HANDLE session;
		TSS_CONTEXT *tssContext;
		TPM_RC rc;
		const char *reason;
		TPM2B_PRIVATE priv_2b;
		BYTE *buf;
		UINT16 written;
		INT32 size;
		Import_Out iout;

		rc = tpm2_create(&tssContext, app_data->dir);
		if (rc) {
			reason="tpm2_create";
			goto import_err;
		}

		if ((app_data->parent & 0xff000000) == 0x40000000) {
			tpm2_load_srk(tssContext, &iin.parentHandle,
				      srk_auth, NULL, app_data->parent, 1);
		} else {
			iin.parentHandle = app_data->parent;
		}
		rc = tpm2_get_session_handle(tssContext, &session,
					     iin.parentHandle,
					     TPM_SE_HMAC,
					     iin.objectPublic.publicArea.nameAlg);
		if (rc) {
			reason="tpm2_get_session_handle";
			goto import_err;
		}

		/* no inner encryption */
		iin.encryptionKey.t.size = 0;
		iin.symmetricAlg.algorithm = TPM_ALG_NULL;

		/* for importable keys the private key is actually the
		 * outer wrapped duplicate structure */
		buffer = privkey->data;
		size = privkey->length;
		TPM2B_PRIVATE_Unmarshal(&iin.duplicate, &buffer, &size);

		buffer = secret->data;
		size = secret->length;
		TPM2B_ENCRYPTED_SECRET_Unmarshal(&iin.inSymSeed, &buffer, &size);
		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&iout,
				 (COMMAND_PARAMETERS *)&iin,
				 NULL,
				 TPM_CC_Import,
				 session, srk_auth, 0,
				 TPM_RH_NULL, NULL, 0);
		if (rc)
			tpm2_flush_handle(tssContext, session);
		reason = "TPM2_Import";

	import_err:
		tpm2_flush_srk(tssContext, iin.parentHandle);
		TSS_Delete(tssContext);
		if (rc) {
			tpm2_error(rc, reason);
			goto err_free;
		}
		buf = priv_2b.t.buffer;
		size = sizeof(priv_2b.t.buffer);
		written = 0;
		TSS_TPM2B_PRIVATE_Marshal(&iout.outPrivate, &written,
					  &buf, &size);
		app_data->priv = OPENSSL_malloc(written);
		if (!app_data->priv)
			goto err_free;
		app_data->priv_len = written;
		memcpy(app_data->priv, priv_2b.t.buffer, written);
	} else {
		app_data->priv = OPENSSL_malloc(privkey->length);
		if (!app_data->priv)
			goto err_free;

		app_data->priv_len = privkey->length;
		memcpy(app_data->priv, privkey->data, app_data->priv_len);
	}

	/* create the new objects to return */
	pkey = tpm2_to_openssl_public(&iin.objectPublic.publicArea);
	if (!pkey) {
		fprintf(stderr, "Failed to allocate a new EVP_KEY\n");
		goto err_free;
	}

	if (empty_auth == 0) {
		app_data->auth = tpm2_get_auth(ui, "TPM Key Password: ", cb_data);
		if (!app_data->auth)
			goto err_free_key;
	}

	if (!(iin.objectPublic.publicArea.objectAttributes.val &
	      TPMA_OBJECT_USERWITHAUTH))
		app_data->req_policy_session = 1;

	if (!tpm2_engine_load_key_policy(app_data, policy))
		goto err_free_key;

	TSSLOADABLE_free(tssl);
	TSSPRIVKEY_free(tpk);

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
	tpm2_set_nvkey_prefix("//nvkey:");
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
	TPM_HANDLE session;

	rc = tpm2_create(&tssContext, app_data->dir);
	if (rc)
		return 0;

	if (app_data->key) {
		key = app_data->key;
		goto out;
	}

	buffer = app_data->priv;
	size = app_data->priv_len;
	TPM2B_PRIVATE_Unmarshal(&in.inPrivate, &buffer, &size);

	buffer = app_data->pub;
	size = app_data->pub_len;
	TPM2B_PUBLIC_Unmarshal(&in.inPublic, &buffer, &size, FALSE);

	if ((app_data->parent & 0xff000000) == 0x81000000) {
		in.parentHandle = app_data->parent;
	} else {
		rc = tpm2_load_srk(tssContext, &in.parentHandle, srk_auth, NULL, app_data->parent, app_data->version);
		if (rc)
			goto out;
	}
	rc = tpm2_get_session_handle(tssContext, &session, in.parentHandle,
				     TPM_SE_HMAC, app_data->name_alg);
	if (rc)
		goto out_flush_srk;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 session, srk_auth, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_Load");
		tpm2_flush_handle(tssContext, session);
	}
	else
		key = out.objectHandle;

 out_flush_srk:
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
	int i;

	for (i = 0; i < app_data->num_commands; i++)
		OPENSSL_free(app_data->commands[i].policy);

	OPENSSL_free(app_data->commands);
	OPENSSL_free(app_data->priv);
	OPENSSL_free(app_data->pub);

	tpm2_rm_tssdir(app_data->dir, app_data->key);

	OPENSSL_free((void *)app_data->dir);

	OPENSSL_free(app_data);
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(tpm2_bind_fn)
