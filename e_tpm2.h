#ifndef _E_TPM2_COMMON_H
#define _E_TPM2_COMMON_H

#include "e_tpm2-rsa.h"
#include "e_tpm2-ecc.h"

#define TPM2_ENGINE_EX_DATA_UNINIT		-1

/* structure pointed to by the RSA object's app_data pointer */
struct app_data {
	TPM_HANDLE parent;
	/* if key is in NV memory */
	TPM_HANDLE key;
	/* otherwise key is specified by blobs */
	void *priv;
	int priv_len;
	void *pub;
	int pub_len;
	char *auth;
	const char *dir;
	int req_policy_session;
	int num_commands;
	struct policy_command *commands;
};

TPM_HANDLE tpm2_load_key(TSS_CONTEXT **tsscp, struct app_data *app_data);
void tpm2_unload_key(TSS_CONTEXT *tssContext, TPM_HANDLE key);
void tpm2_delete(struct app_data *app_data);

#endif
