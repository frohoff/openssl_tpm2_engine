#ifndef _TPM2_COMMON_H
#define _TPM2_COMMON_H
#include "tpm2-asn.h"

#define	T2_AES_KEY_BITS		128
#define T2_AES_KEY_BYTES	(T2_AES_KEY_BITS/8)

/* for use as a TPM_RC return type to indicate this is
 * not a TPM error, so don't process the rc as one */
#define NOT_TPM_ERROR (0xffffffff)

extern TPM_ALG_ID name_alg;

struct policy_command {
	TPM_CC code;
	INT32 size;
	BYTE *policy;
};

enum tpm2_type {
	TPM2_NONE = -1,		/* no defined type yet */
	TPM2_LEGACY = 0,
	TPM2_LOADABLE = 1,
	TPM2_IMPORTABLE = 2,
	TPM2_SEALED = 3,
};

struct policies {
	char *name;
	int num_commands;
	struct policy_command *commands;
};

/* structure pointed to by the RSA object's app_data pointer */
struct app_data {
	enum tpm2_type type;
	TPM_HANDLE parent;
	/* if key is in NV memory */
	TPM_HANDLE key;
	/* otherwise key is specified by blobs */
	void *priv;
	int priv_len;
	TPM2B_PUBLIC Public;
	char *auth;
	const char *dir;
	int req_policy_session;
	/* pols[0] is key policy pols[1+] is authorized policy */
	struct policies *pols;
	int num_pols;
	int empty_auth;
	_Atomic int refs;
	ENGINE *e;
};

void tpm2_error(TPM_RC rc, const char *reason);
TPM_RC tpm2_load_srk(TSS_CONTEXT *tssContext, TPM_HANDLE *h, const char *auth,
		     TPM2B_PUBLIC *pub, TPM_HANDLE handle, enum tpm2_type type);
void tpm2_flush_handle(TSS_CONTEXT *tssContext, TPM_HANDLE h);
EVP_PKEY *tpm2_to_openssl_public(TPMT_PUBLIC *pub);
void tpm2_flush_srk(TSS_CONTEXT *tssContext, TPM_HANDLE hSRK);
TPM_RC tpm2_get_session_handle(TSS_CONTEXT *tssContext, TPM_HANDLE *handle,
			       TPM_HANDLE salt_key, TPM_SE sessionType,
			       TPM_ALG_ID name_alg);
TPM_RC tpm2_init_session(TSS_CONTEXT *tssContext, TPM_HANDLE handle,
			 const struct app_data *app_data, const char **auth);
TPM_RC tpm2_get_bound_handle(TSS_CONTEXT *tssContext, TPM_HANDLE *handle,
			     TPM_HANDLE bind, const char *auth);
TPMI_ECC_CURVE tpm2_curve_name_to_TPMI(const char *name);
int tpm2_curve_to_order(TPMI_ECC_CURVE curve);
int tpm2_curve_name_to_nid(TPMI_ECC_CURVE curve);
TPMI_ECC_CURVE tpm2_nid_to_curve_name(int nid);
TPMI_ECC_CURVE tpm2_get_curve_name(const EC_GROUP *g);
const char *tpm2_curve_name_to_text(TPMI_ECC_CURVE curve);
const char *tpm2_set_unique_tssdir(void);
TPM_RC tpm2_create(TSS_CONTEXT **tsscp, const char *dir);
TPM_RC tpm2_readpublic(TSS_CONTEXT *tssContext, TPM_HANDLE handle,
		       TPMT_PUBLIC *pub);
void tpm2_rm_tssdir(const char *dir);
void tpm2_rm_keyfile(const char *dir, TPM_HANDLE key);
int tpm2_get_public_point(TPM2B_ECC_POINT *tpmpt, const EC_GROUP *group,
			  const EC_POINT *pt);
int tpm2_load_engine_file(const char *filename, struct app_data **app_data,
			  EVP_PKEY **ppkey, UI_METHOD *ui, void *cb_data,
			  const char *srk_auth, int get_key_auth,
			  int public_only);
TPM_HANDLE tpm2_load_key(TSS_CONTEXT **tsscp, const struct app_data *app_data,
			 const char *srk_auth, uint32_t *psession);
void tpm2_unload_key(TSS_CONTEXT *tssContext, TPM_HANDLE key);
void tpm2_delete(struct app_data *app_data);
char *tpm2_get_auth(UI_METHOD *ui, char *input_string, void *cb_data);
TPM_HANDLE tpm2_get_parent_ext(const char *pstr);
TPM_HANDLE tpm2_get_parent(TSS_CONTEXT *tssContext, const char *pstr);
int tpm2_write_tpmfile(const char *file, BYTE *pubkey, int pubkey_len,
		       BYTE *privkey, int privkey_len, int empty_auth,
		       TPM_HANDLE parent, STACK_OF(TSSOPTPOLICY) *sk,
		       int version, ENCRYPTED_SECRET_2B *secret);
TPM_RC tpm2_parse_policy_file(const char *policy_file,
			      STACK_OF(TSSOPTPOLICY) *sk,
			      char *auth, TPMT_HA *digest);
void tpm2_free_policy(STACK_OF(TSSOPTPOLICY) *sk);
void tpm2_get_pcr_lock(TPML_PCR_SELECTION *pcrs, char *arg);
TPM_RC tpm2_pcr_lock_policy(TSS_CONTEXT *tssContext,
			    TPML_PCR_SELECTION *pcrs,
			    STACK_OF(TSSOPTPOLICY) *sk,
			    TPMT_HA *digest);
void tpm2_add_auth_policy(STACK_OF(TSSOPTPOLICY) *sk, TPMT_HA *digest);
void tpm2_add_locality(STACK_OF(TSSOPTPOLICY) *sk, UINT8 locality,
		       TPMT_HA *digest);
EVP_PKEY *openssl_read_public_key(char *filename);
void tpm2_public_template_rsa(TPMT_PUBLIC *pub);
void tpm2_public_template_ecc(TPMT_PUBLIC *pub, TPMI_ECC_CURVE curve);
TPM_RC openssl_to_tpm_public_ecc(TPMT_PUBLIC *pub, EVP_PKEY *pkey);
TPM_RC openssl_to_tpm_public_rsa(TPMT_PUBLIC *pub, EVP_PKEY *pkey);
TPM_RC openssl_to_tpm_public(TPM2B_PUBLIC *pub, EVP_PKEY *pkey);
void openssl_print_errors();
TPM_RC tpm2_ObjectPublic_GetName(NAME_2B *name,	 TPMT_PUBLIC *tpmtPublic);
TPM_RC tpm2_add_signed_policy(STACK_OF(TSSOPTPOLICY) *sk, char *key_file,
			      TPMT_HA *digest);
TPM_RC tpm2_new_signed_policy(char *tpmkey, char *policykey, char *engine,
			      TSSAUTHPOLICY *ap, TPMT_HA *digest, int need_auth);
TPM_RC tpm2_add_policy_secret(TSS_CONTEXT *tssContext, STACK_OF(TSSOPTPOLICY) *sk,
			      TPM_HANDLE handle, TPMT_HA *digest);
TPM_RC tpm2_hmacwrap(EVP_PKEY *parent,
		     NAME_2B *name,
		     const char *label,
		     PRIVATE_2B *p, /* contains the to be encrypted data */
		     ENCRYPTED_SECRET_2B *enc_secret);
TPM_RC tpm2_outerwrap(EVP_PKEY *parent,
		      TPMT_SENSITIVE *s,
		      TPMT_PUBLIC *pub,
		      PRIVATE_2B *p,
		      ENCRYPTED_SECRET_2B *enc_secret);
int tpm2_load_bf(BIO *bf, struct app_data *app_data, const char *srk_auth);
ECDSA_SIG *tpm2_sign_ecc(const struct app_data *ad, const unsigned char *dgst,
			 int dgst_len, char *srk_auth);
int tpm2_ecdh_x(struct app_data *ad, unsigned char **psec, size_t *pseclen,
		const TPM2B_ECC_POINT *inPoint, const char *srk_auth);
int tpm2_rsa_decrypt(const struct app_data *ad, PUBLIC_KEY_RSA_2B *cipherText,
		     unsigned char *to, int padding, int protection,
		     char *srk_auth);
int tpm2_rm_signed_policy(char *tpmkey, int rmnum);
int tpm2_get_signed_policy(char *tpmkey, STACK_OF(TSSAUTHPOLICY) **sk);
#endif
