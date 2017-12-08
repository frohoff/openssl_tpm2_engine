#ifndef _E_TPM2_COMMON_H
#define _E_TPM2_COMMON_H

#include "e_tpm2-rsa.h"
#include "e_tpm2-ecc.h"

#define TPM2_ENGINE_EX_DATA_UNINIT		-1

/* structure pointed to by the RSA object's app_data pointer */
struct app_data
{
	TSS_CONTEXT *tssContext;
	TPM_HANDLE parent;
	TPM_HANDLE key;
	char *auth;
	const char *dir;
};

void tpm2_delete(struct app_data *app_data);

#endif
