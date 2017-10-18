#ifndef _E_TPM2_ECC_H
#define _E_TPM2_ECC_H

void tpm2_bind_key_to_engine_ecc(EVP_PKEY *pkey, void *data);
int tpm2_setup_ecc_methods(void);

#endif
