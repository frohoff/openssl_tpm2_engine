#ifndef _E_TPM2_ECC_H
#define _E_TPM2_ECC_H

void tpm2_bind_key_to_engine_ecc(ENGINE *e, EVP_PKEY *pkey, struct app_data *data);
int tpm2_setup_ecc_methods(void);
void tpm2_teardown_ecc_methods(void);

#endif
