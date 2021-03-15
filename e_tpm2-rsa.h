#ifndef _E_TPM2_RSA_H
#define _E_TPM2_RSA_H

void tpm2_bind_key_to_engine_rsa(EVP_PKEY *pkey, void *data);
int tpm2_setup_rsa_methods(void);
void tpm2_teardown_rsa_methods(void);

#endif
