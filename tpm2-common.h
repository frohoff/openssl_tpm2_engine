#ifndef _TPM2_COMMON_H
#define _TPM2_COMMON_H

void tpm2_error(TPM_RC rc, const char *reason);
TPM_RC tpm2_load_srk(TSS_CONTEXT *tssContext, TPM_HANDLE *h, const char *auth, TPM2B_PUBLIC *pub);
void tpm2_flush_handle(TSS_CONTEXT *tssContext, TPM_HANDLE h);
EVP_PKEY *tpm2_to_openssl_public(TPMT_PUBLIC *pub);
void tpm2_flush_srk(TSS_CONTEXT *tssContext);
TPM_RC tpm2_get_hmac_handle(TSS_CONTEXT *tssContext, TPM_HANDLE *handle,
			    TPM_HANDLE salt_key);

#endif
