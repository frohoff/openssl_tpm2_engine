/*
 * Copyright (C) 2021 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * Some portions of the TSS routines are
 * (c) Copyright IBM Corporation 2015 - 2019
 */

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define EXT_TPM_RH_OWNER	TPM2_RH_OWNER
#define EXT_TPM_RH_PLATFORM	TPM2_RH_PLATFORM
#define EXT_TPM_RH_ENDORSEMENT	TPM2_RH_ENDORSEMENT
#define EXT_TPM_RH_NULL		TPM2_RH_NULL
#define INT_TPM_RH_NULL		ESYS_TR_RH_NULL

#define TSS_CONTEXT		ESYS_CONTEXT

#define MAX_RESPONSE_SIZE	TPM2_MAX_RESPONSE_SIZE
#define MAX_RSA_KEY_BYTES	TPM2_MAX_RSA_KEY_BYTES
#define MAX_ECC_CURVES		TPM2_MAX_ECC_CURVES
#define MAX_ECC_KEY_BYTES	TPM2_MAX_ECC_KEY_BYTES
#define MAX_SYM_DATA		TPM2_MAX_SYM_DATA

#define AES_128_BLOCK_SIZE_BYTES	16

/*
 * The TCG defines all begin TPM_ but for some unknown reason Intel
 * ignored this and all its defines begin TPM2_
 */

#define TPM_RC_SUCCESS		TPM2_RC_SUCCESS
#define TPM_RC_SYMMETRIC	TPM2_RC_SYMMETRIC
#define TPM_RC_ASYMMETRIC	TPM2_RC_ASYMMETRIC
#define TPM_RC_CURVE		TPM2_RC_CURVE
#define TPM_RC_KEY_SIZE		TPM2_RC_KEY_SIZE
#define TPM_RC_KEY		TPM2_RC_KEY
#define TPM_RC_VALUE		TPM2_RC_VALUE
#define TPM_RC_POLICY		TPM2_RC_POLICY
#define TPM_RC_FAILURE		TPM2_RC_FAILURE

#define RC_VER1			TPM2_RC_VER1
#define RC_FMT1			TPM2_RC_FMT1

#define TPM_EO_EQ		TPM2_EO_EQ
#define TPM_EO_NEQ		TPM2_EO_NEQ
#define TPM_EO_SIGNED_GT	TPM2_EO_SIGNED_GT
#define TPM_EO_UNSIGNED_GT	TPM2_EO_UNSIGNED_GT
#define TPM_EO_SIGNED_LT	TPM2_EO_SIGNED_LT
#define TPM_EO_UNSIGNED_LT	TPM2_EO_UNSIGNED_LT
#define TPM_EO_SIGNED_GE	TPM2_EO_SIGNED_GE
#define TPM_EO_UNSIGNED_GE	TPM2_EO_UNSIGNED_GE
#define TPM_EO_SIGNED_LE	TPM2_EO_SIGNED_LE
#define TPM_EO_UNSIGNED_LE	TPM2_EO_UNSIGNED_LE
#define TPM_EO_BITSET		TPM2_EO_BITSET
#define TPM_EO_BITCLEAR		TPM2_EO_BITCLEAR

#define TPM_CC_PolicyPCR	TPM2_CC_PolicyPCR
#define TPM_CC_PolicyAuthValue	TPM2_CC_PolicyAuthValue
#define TPM_CC_PolicyCounterTimer	TPM2_CC_PolicyCounterTimer

#define TPM_ST_HASHCHECK	TPM2_ST_HASHCHECK

#define TPM_RH_OWNER		ESYS_TR_RH_OWNER
#define TPM_RH_PLATFORM		ESYS_TR_RH_PLATFORM
#define TPM_RH_ENDORSEMENT	ESYS_TR_RH_ENDORSEMENT
#define TPM_RH_NULL		ESYS_TR_NONE

#define TPM_HT_PERMANENT	TPM2_HT_PERMANENT
#define TPM_HT_TRANSIENT	TPM2_HT_TRANSIENT
#define TPM_HT_PERSISTENT	TPM2_HT_PERSISTENT

#define TPM_HANDLE		ESYS_TR
#define TPM_RC			TPM2_RC
#define TPM_CC			TPM2_CC

#define TPM_ALG_ID		TPM2_ALG_ID
#define TPM_SE			TPM2_SE
#define TPM_SE_HMAC		TPM2_SE_HMAC
#define TPM_SE_POLICY		TPM2_SE_POLICY
#define TPM_CAP			TPM2_CAP
#define TPM_CAP_ECC_CURVES	TPM2_CAP_ECC_CURVES
#define TPM_EO			TPM2_EO

#define TPM_ECC_NONE		TPM2_ECC_NONE
#define TPM_ECC_NIST_P192	TPM2_ECC_NIST_P192
#define TPM_ECC_NIST_P224	TPM2_ECC_NIST_P224
#define TPM_ECC_NIST_P256	TPM2_ECC_NIST_P256
#define TPM_ECC_NIST_P384	TPM2_ECC_NIST_P384
#define TPM_ECC_NIST_P521	TPM2_ECC_NIST_P521
#define TPM_ECC_BN_P256		TPM2_ECC_BN_P256
#define TPM_ECC_BN_P638		TPM2_ECC_BN_P638
#define TPM_ECC_SM2_P256	TPM2_ECC_SM2_P256

#define TPM_ALG_NULL		TPM2_ALG_NULL
#define TPM_ALG_SHA1		TPM2_ALG_SHA1
#define TPM_ALG_SHA256		TPM2_ALG_SHA256
#define TPM_ALG_SHA384		TPM2_ALG_SHA384
#define TPM_ALG_SHA512		TPM2_ALG_SHA512
#define TPM_ALG_AES		TPM2_ALG_AES
#define TPM_ALG_CFB		TPM2_ALG_CFB
#define TPM_ALG_RSA		TPM2_ALG_RSA
#define TPM_ALG_ECC		TPM2_ALG_ECC
#define TPM_ALG_KEYEDHASH	TPM2_ALG_KEYEDHASH
#define TPM_ALG_RSAES		TPM2_ALG_RSAES
#define TPM_ALG_OAEP		TPM2_ALG_OAEP
#define TPM_ALG_ECDSA		TPM2_ALG_ECDSA

/* the odd TPMA_OBJECT_  type is wrong too */

#define TPMA_OBJECT_SIGN	TPMA_OBJECT_SIGN_ENCRYPT

/* Intel and IBM have slightly different names for all the 2B structures */

#define NAME_2B			TPM2B_NAME
#define DATA_2B			TPM2B_DATA
#define PRIVATE_2B		TPM2B_PRIVATE
#define ENCRYPTED_SECRET_2B	TPM2B_ENCRYPTED_SECRET
#define KEY_2B			TPM2B_KEY
#define TPM2B_KEY		TPM2B_DATA
#define DIGEST_2B		TPM2B_DIGEST
#define ECC_PARAMETER_2B	TPM2B_ECC_PARAMETER
#define SENSITIVE_DATA_2B	TPM2B_SENSITIVE_DATA
#define PUBLIC_KEY_RSA_2B	TPM2B_PUBLIC_KEY_RSA

#define FALSE			0
#define TRUE			1

typedef struct {
	uint16_t size;
	BYTE buffer[];
} TPM2B;

#define TSS_CONVERT_MARSHAL(TYPE, PTR)				\
static inline TPM_RC						\
TSS_##TYPE##_Marshal(const TYPE *source, UINT16 *written,	\
		     BYTE **buffer, INT32 *size)		\
{								\
	size_t offset = 0;					\
	TPM_RC rc;						\
								\
	rc = Tss2_MU_##TYPE##_Marshal(PTR source, *buffer, *size, &offset); \
								\
	*buffer += offset;					\
	*size -= offset;					\
	*written += offset;					\
								\
	return rc;						\
}
#define TSS_CONVERT_UNMARSHAL(TYPE, ARG)			\
static inline TPM_RC						\
TYPE##_Unmarshal##ARG(TYPE *dest,					\
		 BYTE **buffer, INT32 *size)			\
{								\
	size_t offset = 0;					\
	TPM_RC rc;						\
								\
	memset(dest, 0, sizeof(TYPE));				\
	rc = Tss2_MU_##TYPE##_Unmarshal(*buffer, *size, &offset, dest);	\
								\
	*buffer += offset;					\
	*size -= offset;					\
								\
	return rc;						\
}

TSS_CONVERT_MARSHAL(TPMT_PUBLIC, )
TSS_CONVERT_MARSHAL(UINT16, *)
TSS_CONVERT_MARSHAL(TPMT_SENSITIVE, )
TSS_CONVERT_MARSHAL(TPM2B_ECC_POINT, )
TSS_CONVERT_MARSHAL(TPM2B_DIGEST, )
TSS_CONVERT_MARSHAL(TPM2B_PUBLIC, )
TSS_CONVERT_MARSHAL(TPM2B_PRIVATE, )

TSS_CONVERT_UNMARSHAL(TPML_PCR_SELECTION, )
TSS_CONVERT_UNMARSHAL(TPM2B_PRIVATE, )
TSS_CONVERT_UNMARSHAL(TPM2B_PUBLIC, X)
TSS_CONVERT_UNMARSHAL(TPM2B_ENCRYPTED_SECRET, )
TSS_CONVERT_UNMARSHAL(UINT16, )
TSS_CONVERT_UNMARSHAL(UINT32, )

#define ARRAY_SIZE(A) (sizeof(A)/sizeof(A[0]))

#define TPM2B_PUBLIC_Unmarshal(A, B, C, D) TPM2B_PUBLIC_UnmarshalX(A, B, C)
#define TPM_EO_Unmarshal	UINT16_Unmarshal
#define TPM_CC_Unmarshal	UINT32_Unmarshal

#define VAL(X) X
#define VAL_2B(X, MEMBER) X.MEMBER
#define VAL_2B_P(X, MEMBER) X->MEMBER

static const struct {
	TPM_ALG_ID alg;
	const char *name;
	int size;
} TSS_Hashes[] = {
	{ TPM_ALG_SHA1,   "sha1",   SHA_DIGEST_LENGTH },
	{ TPM_ALG_SHA256, "sha256", SHA256_DIGEST_LENGTH },
	{ TPM_ALG_SHA384, "sha384", SHA384_DIGEST_LENGTH },
	{ TPM_ALG_SHA512, "sha512", SHA512_DIGEST_LENGTH }
};

static inline void
intel_auth_helper(TSS_CONTEXT *tssContext, TPM_HANDLE auth, const char *authVal)
{
	TPM2B_AUTH authVal2B;

	if (authVal) {
		authVal2B.size = strlen(authVal);
		memcpy(authVal2B.buffer, authVal, authVal2B.size);
	} else {
		authVal2B.size = 0;
	}
	Esys_TR_SetAuth(tssContext, auth, &authVal2B);
}

static inline void
intel_sess_helper(TSS_CONTEXT *tssContext, TPM_HANDLE auth, TPMA_SESSION flags)
{
	Esys_TRSess_SetAttributes(tssContext, auth, flags,
				  TPMA_SESSION_CONTINUESESSION | flags);
}

static inline TPM_HANDLE
intel_handle(TPM_HANDLE h)
{
	if (h == 0)
		return ESYS_TR_NONE;
	return h;
}

static inline void
TSS_Delete(TSS_CONTEXT *tssContext)
{
	TSS2_TCTI_CONTEXT *tcti_ctx;
	TPM_RC rc;

	rc = Esys_GetTcti(tssContext, &tcti_ctx);
	Esys_Finalize(&tssContext);
	if (rc == TPM_RC_SUCCESS)
		Tss2_TctiLdr_Finalize(&tcti_ctx);
}

static inline TPM_RC
TSS_Create(TSS_CONTEXT **tssContext)
{
	TPM_RC rc;
	TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
	char *intType;
	char *tctildr = NULL;

	intType = getenv("TPM_INTERFACE_TYPE");
	/*
	 * FIXME: This should be way more sophisticated, but it's
	 * enough to get the simulator tests running
	 */
	if (intType) {
		if (strcmp("socsim", intType) == 0) {
			tctildr = "mssim";
		} else if (strcmp("dev", intType) == 0) {
			tctildr = "device";
		} else {
			fprintf(stderr, "Unknown TPM_INTERFACE_TYPE %s\n", intType);
		}
	}

	rc = Tss2_TctiLdr_Initialize(tctildr, &tcti_ctx);
	if (rc)
		return rc;

	rc =  Esys_Initialize(tssContext, tcti_ctx, NULL);

	return rc;
}

static inline int
TSS_GetDigestSize(TPM_ALG_ID alg) {
	int i;

	for (i = 0; i < ARRAY_SIZE(TSS_Hashes); i++)
		if (TSS_Hashes[i].alg == alg)
			return TSS_Hashes[i].size;
	return -1;
}

static inline int
TSS_Hash_GetMd(const EVP_MD **md, TPM_ALG_ID alg) {
	int i;

	for (i = 0; i < ARRAY_SIZE(TSS_Hashes); i++)
		if (TSS_Hashes[i].alg == alg) {
			*md = EVP_get_digestbyname(TSS_Hashes[i].name);
			return 0;
		}
	return TPM_RC_FAILURE;
}

/* copied with modifications from the IBM TSS tsscrypto.c */
static inline TPM_RC
TSS_Hash_Generate(TPMT_HA *digest, ...)
{
	TPM_RC rc = 0;
	int length;
	uint8_t *buffer;
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	va_list ap;

	va_start(ap, digest);

	mdctx = EVP_MD_CTX_create();
        if (mdctx == NULL) {
		fprintf(stderr, "TSS_Hash_Generate: EVP_MD_CTX_create failed\n");
		rc = TPM_RC_FAILURE;
		goto out;
	}

	rc = TSS_Hash_GetMd(&md, digest->hashAlg);
	if (rc) {
		fprintf(stderr, "TSS_HASH_GENERATE: Unknown hash %d\n",
			digest->hashAlg);
		goto out;
	}

	rc = EVP_DigestInit_ex(mdctx, md, NULL);
	if (rc != 1) {
		fprintf(stderr, "TSS_Hash_Generate: failed to init digest\n");
		ERR_print_errors_fp(stderr);
		rc = TPM_RC_FAILURE;
		goto out;
	}

	rc = TPM_RC_FAILURE;
	for (;;) {
		length = va_arg(ap, int);		/* first vararg is the length */
		buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
		if (buffer == NULL)			/* loop until a NULL buffer terminates */
			break;
		if (length < 0) {
			fprintf(stderr, "TSS_Hash_Generate: Length is negative\n");
			goto out_free;
		}
		if (length != 0) {
			EVP_DigestUpdate(mdctx, buffer, length);
		}
	}

	EVP_DigestFinal_ex(mdctx, (uint8_t *)&digest->digest, NULL);
	rc = TPM_RC_SUCCESS;
 out_free:
	EVP_MD_CTX_destroy(mdctx);
 out:
	va_end(ap);
	return rc;
}

/* copied with modifications from the IBM TSS tsscrypto.c */
static inline TPM_RC
TSS_HMAC_Generate(TPMT_HA *digest, const TPM2B_KEY *hmacKey, ...)

{
	TPM_RC	rc;
	const EVP_MD *md;	/* message digest method */
#if OPENSSL_VERSION_NUMBER < 0x10100000
	HMAC_CTX ctx;
#else
	HMAC_CTX *ctx;
#endif
	int length;
	uint8_t *buffer;
	va_list	ap;

	va_start(ap, hmacKey);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	HMAC_CTX_init(&ctx);
#else
	ctx = HMAC_CTX_new();
#endif
	rc = TSS_Hash_GetMd(&md, digest->hashAlg);
	if (rc)
		goto out;

#if OPENSSL_VERSION_NUMBER < 0x10100000
	rc = HMAC_Init_ex(&ctx,
			  hmacKey->buffer, hmacKey->size,	/* HMAC key */
			  md,					/* message digest method */
			  NULL);
#else
	rc = HMAC_Init_ex(ctx,
			  hmacKey->buffer, hmacKey->size,	/* HMAC key */
			  md,					/* message digest method */
			  NULL);
#endif

	if (rc == 0) {
		rc = TPM_RC_FAILURE;
		goto out;
	}

	for (;;) {
		length = va_arg(ap, int);		/* first vararg is the length */
		buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
		if (buffer == NULL)			/* loop until a NULL buffer terminates */
			break;
		if (length < 0) {
			fprintf(stderr, "TSS_HMAC_Generate: Length is negative\n");
			rc = TPM_RC_FAILURE;
			goto out_free;
		}
#if OPENSSL_VERSION_NUMBER < 0x10100000
		rc = HMAC_Update(&ctx, buffer, length);
#else
		rc = HMAC_Update(ctx, buffer, length);
#endif
		if (rc == 0) {
			fprintf(stderr, "TSS_HMAC_Generate: HMAC_Update failed\n");
			rc = TPM_RC_FAILURE;
			goto out_free;
		}
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000
	rc = HMAC_Final(&ctx, (uint8_t *)&digest->digest, NULL);
#else
	rc = HMAC_Final(ctx, (uint8_t *)&digest->digest, NULL);
#endif
	if (rc == 0)
		rc = TPM_RC_FAILURE;
	else
		rc = TPM_RC_SUCCESS;

 out_free:
#if OPENSSL_VERSION_NUMBER < 0x10100000
	HMAC_CTX_cleanup(&ctx);
#else
	HMAC_CTX_free(ctx);
#endif
 out:
	va_end(ap);
	return rc;
}

/* copied with modifications from the IBM TSS tsscrypto.c */
static inline void
TSS_XOR(unsigned char *out,
	const unsigned char *in1,
	const unsigned char *in2,
	size_t length)
{
	size_t i;

	for (i = 0 ; i < length ; i++)
		out[i] = in1[i] ^ in2[i];
}

/* copied with modifications from the IBM TSS tsscrypto.c */
static inline TPM_RC
TSS_AES_EncryptCFB(uint8_t *dOut, uint32_t keySizeInBits, uint8_t *key,
		   uint8_t *iv,uint32_t dInSize, uint8_t *dIn)
{
	TPM_RC rc = 0;
	int blockSize;
	AES_KEY aeskey;
	int32_t dSize;         /* signed version of dInSize */

	/* Create AES encryption key token */
	rc = AES_set_encrypt_key(key, keySizeInBits, &aeskey);
	if (rc != 0) {
		fprintf(stderr, "TSS_AES_EncryptCFB: Error setting openssl AES encryption key\n");
		return TPM_RC_FAILURE;  /* should never occur, null pointers or bad bit size */
	}

	/* Encrypt the current IV into the new IV, XOR in the data, and copy to output */
	for(dSize = (int32_t)dInSize ; dSize > 0 ; dSize -= 16, dOut += 16, dIn += 16) {
		/* Encrypt the current value of the IV to the intermediate value.  Store in old iv,
		   since it's not needed anymore. */
		AES_encrypt(iv, iv, &aeskey);
		blockSize = (dSize < 16) ? dSize : 16;	/* last block can be < 16 */
		TSS_XOR(dOut, dIn, iv, blockSize);
		memcpy(iv, dOut, blockSize);
	}

	return TPM_RC_SUCCESS;
}

static inline TPM_RC
TSS_TPM2B_Create(TPM2B *target, uint8_t *buffer, uint16_t size,
		 uint16_t targetSize)
{
	if (size > targetSize)
		return TSS2_MU_RC_INSUFFICIENT_BUFFER;
	target->size = size;
	if (size)
		memmove(target->buffer, buffer, size);
	return TPM_RC_SUCCESS;
}

/*
 * copied with modifications from the IBM TSS tsscrypto.c which is in
 * turn based on the Trusted Platform Module Library Part 4:
 * Supporting Routines B B.8.6.3 _cpri__KDFe()
 */
static inline TPM_RC
TSS_KDFE(uint8_t *keyStream, TPM_ALG_ID hashAlg, const TPM2B *key,
	 const char *label, const TPM2B *contextU, const TPM2B *contextV,
	 uint32_t sizeInBits)
{
	TPM_RC	rc = 0;
	uint32_t 	bytes = ((sizeInBits + 7) / 8);	/* bytes left to produce */
	uint8_t	*stream;
	uint16_t    bytesThisPass;			/* in one Hash operation */
	uint32_t	counter;    			/* counter value */
	uint32_t 	counterNbo;			/* counter in big endian */
	TPMT_HA 	digest;				/* result for this pass */

	digest.hashAlg = hashAlg;			/* for TSS_Hash_Generate() */
	bytesThisPass = TSS_GetDigestSize(hashAlg);	/* start with hashAlg sized chunks */
	if (bytesThisPass == 0) {
		fprintf(stderr, "TSS_KDFE: KDFe failed\n");
		rc = TPM_RC_FAILURE;
	}

	/* Generate required bytes */
	for (stream = keyStream, counter = 1 ;	/* beginning of stream, KDFe counter starts at 1 */
	     (rc == 0) && bytes > 0 ;				/* bytes left to produce */
	     stream += bytesThisPass, bytes -= bytesThisPass, counter++) {
		/* last pass, can be less than hashAlg sized chunks */
		if (bytes < bytesThisPass) {
			bytesThisPass = bytes;
		}
		counterNbo = htobe32(counter);	/* counter for this pass in BE format */

		rc = TSS_Hash_Generate(&digest,				/* largest size of a digest */
				       sizeof(uint32_t), &counterNbo,	/* KDFe i2 counter */
				       key->size, key->buffer,
				       strlen(label) + 1, label,	/* KDFe label, use NUL as the KDFe
								   00 byte */
				       contextU->size, contextU->buffer,	/* KDFe Context */
				       contextV->size, contextV->buffer,	/* KDFe Context */
				       0, NULL);
		memcpy(stream, &digest.digest, bytesThisPass);
	}
	return rc;
}

/*
 * copied with modifications from the IBM TSS tsscrypto.c which is in
 * turn based on the Trusted Platform Module Library Part 4:
 * Supporting Routines B B.8.6.2 _cpri__KDFa()
 */
static inline TPM_RC
TSS_KDFA(uint8_t *keyStream, TPM_ALG_ID hashAlg, const TPM2B *key,
	 const char *label, const TPM2B *contextU, const TPM2B *contextV,
	 uint32_t sizeInBits)
{
	TPM_RC	rc = 0;
	uint32_t 	bytes = ((sizeInBits + 7) / 8);	/* bytes left to produce */
	uint8_t	*stream;
	uint32_t 	sizeInBitsNbo = htobe32(sizeInBits);	/* KDFa L2 */
	uint16_t    bytesThisPass;			/* in one HMAC operation */
	uint32_t	counter;    			/* counter value */
	uint32_t 	counterNbo;			/* counter in big endian */
	TPMT_HA 	hmac;				/* hmac result for this pass */

	hmac.hashAlg = hashAlg;			/* for TSS_HMAC_Generate() */
	bytesThisPass = TSS_GetDigestSize(hashAlg);	/* start with hashAlg sized chunks */
	if (bytesThisPass == 0) {
		fprintf(stderr, "TSS_KDFA: KDFa failed\n");
		rc = TPM_RC_FAILURE;
	}
	/* Generate required bytes */
	for (stream = keyStream, counter = 1 ;	/* beginning of stream, KDFa counter starts at 1 */
	     (rc == 0) && bytes > 0 ;				/* bytes left to produce */
	     stream += bytesThisPass, bytes -= bytesThisPass, counter++) {

		/* last pass, can be less than hashAlg sized chunks */
		if (bytes < bytesThisPass) {
			bytesThisPass = bytes;
		}
		counterNbo = htobe32(counter);	/* counter for this pass in BE format */

		rc = TSS_HMAC_Generate(&hmac,				/* largest size of an HMAC */
				       (const TPM2B_KEY *)key,
				       sizeof(uint32_t), &counterNbo,	/* KDFa i2 counter */
				       strlen(label) + 1, label,	/* KDFa label, use NUL as the KDFa
									   00 byte */
				       contextU->size, contextU->buffer,	/* KDFa Context */
				       contextV->size, contextV->buffer,	/* KDFa Context */
				       sizeof(uint32_t), &sizeInBitsNbo,	/* KDFa L2 */
				       0, NULL);
		memcpy(stream, &hmac.digest, bytesThisPass);
	}
	return rc;
}

static inline void
tpm2_error(TPM_RC rc, const char *reason)
{
	const char *msg;

	fprintf(stderr, "%s failed with %d\n", reason, rc);
	msg = Tss2_RC_Decode(rc);
	fprintf(stderr, "%s\n", msg);
}


static inline TPM_RC
tpm2_GetCapability(TSS_CONTEXT *tssContext, TPM_CAP capability,
		   UINT32 property, UINT32 propertyCount,
		   TPMI_YES_NO *moreData, TPMS_CAPABILITY_DATA *capabilityData)
{
	TPM_RC rc;
	TPMS_CAPABILITY_DATA *cd;

	rc = Esys_GetCapability(tssContext, ESYS_TR_NONE, ESYS_TR_NONE,
				  ESYS_TR_NONE, capability, property,
				  propertyCount, moreData, &cd);

	if (rc)
		return rc;

	*capabilityData = *cd;
	free(cd);

	return rc;
}

static inline TPM_RC
tpm2_Import(TSS_CONTEXT *tssContext, TPM_HANDLE parentHandle,
	    DATA_2B *encryptionKey, TPM2B_PUBLIC *objectPublic,
	    PRIVATE_2B *duplicate, ENCRYPTED_SECRET_2B *inSymSeed,
	    TPMT_SYM_DEF_OBJECT *symmetricAlg, PRIVATE_2B *outPrivate,
	    TPM_HANDLE auth, const char *authVal)
{
	PRIVATE_2B *out;
	TPM_RC rc;

	intel_auth_helper(tssContext, parentHandle, authVal);
	intel_sess_helper(tssContext, auth, TPMA_SESSION_DECRYPT);
	rc = Esys_Import(tssContext, parentHandle, auth, ESYS_TR_NONE,
			 ESYS_TR_NONE, encryptionKey, objectPublic,
			 duplicate, inSymSeed, symmetricAlg, &out);
	if (rc)
		return rc;

	*outPrivate = *out;
	free(out);

	return rc;
}

static inline TPM_RC
tpm2_Create(TSS_CONTEXT *tssContext, TPM_HANDLE parentHandle,
	    TPM2B_SENSITIVE_CREATE *inSensitive, TPM2B_PUBLIC *inPublic,
	    PRIVATE_2B *outPrivate, TPM2B_PUBLIC *outPublic,
	    TPM_HANDLE auth, const char *authVal)
{
	TPM_RC rc;
	PRIVATE_2B *opriv;
	TPM2B_PUBLIC *opub;
	DATA_2B outsideInfo;
	TPML_PCR_SELECTION creationPCR;

	outsideInfo.size = 0;
	creationPCR.count = 0;

	intel_auth_helper(tssContext, parentHandle, authVal);
	intel_sess_helper(tssContext, auth, TPMA_SESSION_DECRYPT);
	rc = Esys_Create(tssContext, parentHandle, auth,
			 ESYS_TR_NONE, ESYS_TR_NONE, inSensitive,
			 inPublic, &outsideInfo, &creationPCR, &opriv,
			 &opub, NULL, NULL, NULL);

	if (rc)
		return rc;

	*outPublic = *opub;
	free(opub);
	*outPrivate = *opriv;
	free(opriv);

	return rc;
}

static inline TPM_RC
tpm2_Unseal(TSS_CONTEXT *tssContext, TPM_HANDLE itemHandle,
	    SENSITIVE_DATA_2B *outData, TPM_HANDLE auth,
	    const char *authVal)
{
	SENSITIVE_DATA_2B *out;
	TPM_RC rc;

	intel_auth_helper(tssContext, itemHandle, authVal);
	intel_sess_helper(tssContext, auth, TPMA_SESSION_ENCRYPT);
	rc = Esys_Unseal(tssContext, itemHandle, auth, ESYS_TR_NONE,
			 ESYS_TR_NONE, &out);
	if (rc)
		return rc;

	*outData = *out;
	free(out);

	return rc;
}

static inline TPM_RC
tpm2_EvictControl(TSS_CONTEXT *tssContext, TPM_HANDLE objectHandle,
		  TPM_HANDLE persistentHandle)
{
	TPM_HANDLE out;

	return Esys_EvictControl(tssContext, TPM_RH_OWNER, objectHandle,
				 ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				 persistentHandle, &out);
}

static inline TPM_RC
tpm2_ReadPublic(TSS_CONTEXT *tssContext, TPM_HANDLE objectHandle,
		TPMT_PUBLIC *pub, TPM_HANDLE auth)
{
	TPM2B_PUBLIC *out;
	TPM_RC rc;

	if (auth != TPM_RH_NULL)
		intel_sess_helper(tssContext, auth, TPMA_SESSION_ENCRYPT);

	rc = Esys_ReadPublic(tssContext, objectHandle, auth, ESYS_TR_NONE,
			     ESYS_TR_NONE, &out, NULL, NULL);
	if (rc)
		return rc;

	if (pub)
		*pub = out->publicArea;
	free(out);

	return rc;
}

static inline TPM_RC
tpm2_RSA_Decrypt(TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle,
		 PUBLIC_KEY_RSA_2B *cipherText, TPMT_RSA_DECRYPT *inScheme,
		 PUBLIC_KEY_RSA_2B *message,
		 TPM_HANDLE auth, const char *authVal, int flags)
{
	PUBLIC_KEY_RSA_2B *out;
	DATA_2B label;
	TPM_RC rc;

	label.size = 0;

	intel_auth_helper(tssContext, keyHandle, authVal);
	intel_sess_helper(tssContext, auth, flags);
	rc = Esys_RSA_Decrypt(tssContext, keyHandle, auth, ESYS_TR_NONE,
			      ESYS_TR_NONE, cipherText,
			      inScheme, &label, &out);

	if (rc)
		return rc;

	*message = *out;
	free(out);

	return rc;
}

static inline TPM_RC
tpm2_Sign(TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle, DIGEST_2B *digest,
	  TPMT_SIG_SCHEME *inScheme, TPMT_SIGNATURE *signature,
	  TPM_HANDLE auth, const char *authVal)
{
	TPM_RC rc;
	TPMT_TK_HASHCHECK validation;
	TPMT_SIGNATURE *out;

	validation.tag = TPM_ST_HASHCHECK;
	validation.hierarchy = EXT_TPM_RH_NULL;
	validation.digest.size = 0;

	intel_auth_helper(tssContext, keyHandle, authVal);
	intel_sess_helper(tssContext, auth, 0);
	rc = Esys_Sign(tssContext, keyHandle, auth, ESYS_TR_NONE,
		       ESYS_TR_NONE, digest, inScheme, &validation, &out);

	if (rc)
		return rc;

	*signature = *out;
	free(out);

	return rc;
}

static inline TPM_RC
tpm2_ECDH_ZGen(TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle,
	       TPM2B_ECC_POINT *inPoint, TPM2B_ECC_POINT *outPoint,
	       TPM_HANDLE auth, const char *authVal)
{
	TPM2B_ECC_POINT *out;
	TPM_RC rc;

	intel_auth_helper(tssContext, keyHandle, authVal);
	intel_sess_helper(tssContext, auth, TPMA_SESSION_ENCRYPT);
	rc = Esys_ECDH_ZGen(tssContext, keyHandle, auth, ESYS_TR_NONE,
			    ESYS_TR_NONE, inPoint, &out);

	if (rc)
		return rc;

	*outPoint = *out;
	free(out);

	return rc;
}

static inline TPM_RC
tpm2_CreatePrimary(TSS_CONTEXT *tssContext, TPM_HANDLE primaryHandle,
		   TPM2B_SENSITIVE_CREATE *inSensitive,
		   TPM2B_PUBLIC *inPublic, TPM_HANDLE *objectHandle,
		   TPM2B_PUBLIC *outPublic,
		   TPM_HANDLE auth, const char *authVal)
{
	TPM2B_DATA outsideInfo;
	TPML_PCR_SELECTION creationPcr;
	TPM2B_PUBLIC *opub;
	TPM_RC rc;

	/* FIXME will generate wrong value for NULL hierarchy */
	primaryHandle = intel_handle(primaryHandle);

	outsideInfo.size = 0;
	creationPcr.count = 0;

	intel_auth_helper(tssContext, primaryHandle, authVal);
	intel_sess_helper(tssContext, auth, TPMA_SESSION_DECRYPT);
	rc = Esys_CreatePrimary(tssContext, primaryHandle, auth, ESYS_TR_NONE,
				ESYS_TR_NONE, inSensitive, inPublic,
				&outsideInfo, &creationPcr, objectHandle,
				&opub, NULL, NULL, NULL);
	if (rc)
		return rc;

	if (outPublic)
		*outPublic = *opub;
	free(opub);

	return rc;
}

static inline TPM_RC
tpm2_FlushContext(TSS_CONTEXT *tssContext, TPM_HANDLE flushHandle)
{
	return Esys_FlushContext(tssContext, flushHandle);
}

static inline TPM_RC
tpm2_ECC_Parameters(TSS_CONTEXT *tssContext, TPMI_ECC_CURVE curveID,
		    TPMS_ALGORITHM_DETAIL_ECC *parameters)
{
	TPMS_ALGORITHM_DETAIL_ECC *out;
	TPM_RC rc;

	rc = Esys_ECC_Parameters(tssContext, ESYS_TR_NONE, ESYS_TR_NONE,
				 ESYS_TR_NONE, curveID, &out);
	if (rc)
		return rc;

	*parameters = *out;
	free(out);

	return rc;
}

static inline TPM_RC
tpm2_StartAuthSession(TSS_CONTEXT *tssContext, TPM_HANDLE tpmKey,
		      TPM_HANDLE bind, TPM_SE sessionType,
		      TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash,
		      TPM_HANDLE *sessionHandle,
		      const char *bindPassword)
{
	bind = intel_handle(bind);
	tpmKey = intel_handle(tpmKey);
	if (bind != ESYS_TR_NONE)
		intel_auth_helper(tssContext, bind, bindPassword);

	return Esys_StartAuthSession(tssContext, tpmKey, bind, ESYS_TR_NONE,
				     ESYS_TR_NONE, ESYS_TR_NONE, NULL,
				     sessionType, symmetric, authHash,
				     sessionHandle);
}

static inline TPM_RC
tpm2_Load(TSS_CONTEXT *tssContext, TPM_HANDLE parentHandle,
	  PRIVATE_2B *inPrivate, TPM2B_PUBLIC *inPublic,
	  TPM_HANDLE *objectHandle,
	  TPM_HANDLE auth, const char *authVal)
{
	intel_auth_helper(tssContext, parentHandle, authVal);
	intel_sess_helper(tssContext, auth, 0);
	return Esys_Load(tssContext, parentHandle, auth, ESYS_TR_NONE,
			 ESYS_TR_NONE, inPrivate, inPublic, objectHandle);
}

static inline TPM_RC
tpm2_PolicyPCR(TSS_CONTEXT *tssContext, TPM_HANDLE policySession,
	       DIGEST_2B *pcrDigest, TPML_PCR_SELECTION *pcrs)
{
	return Esys_PolicyPCR(tssContext, policySession,
			      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			      pcrDigest, pcrs);
}

static inline TPM_RC
tpm2_PolicyAuthValue(TSS_CONTEXT *tssContext, TPM_HANDLE policySession)
{
	return Esys_PolicyAuthValue(tssContext, policySession,
				    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
}

static inline TPM_RC
tpm2_PolicyCounterTimer(TSS_CONTEXT *tssContext, TPM_HANDLE policySession,
			DIGEST_2B *operandB, UINT16 offset,
			TPM_EO operation)
{
	return Esys_PolicyCounterTimer(tssContext, policySession,
				       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				       operandB, offset, operation);
}

static inline TPM_HANDLE
tpm2_handle_ext(TSS_CONTEXT *tssContext, TPM_HANDLE esysh)
{
	TPM2_HANDLE realh = 0;

	Esys_TR_GetTpmHandle(tssContext, esysh, &realh);

	return realh;
}

static inline TPM_HANDLE
tpm2_handle_int(TSS_CONTEXT *tssContext, TPM_HANDLE realh)
{
	TPM_HANDLE esysh = 0;

	/* ***ing thing doesn't transform permanent handles */
	if ((realh >> 24) == TPM_HT_PERMANENT) {
		switch (realh) {
		case TPM2_RH_OWNER:
			return TPM_RH_OWNER;
		case TPM2_RH_PLATFORM:
			return TPM_RH_PLATFORM;
		case TPM2_RH_ENDORSEMENT:
			return TPM_RH_ENDORSEMENT;
		case TPM2_RH_NULL:
			return ESYS_TR_RH_NULL;
		default:
			return 0;
		}
	}

	Esys_TR_FromTPMPublic(tssContext, realh, ESYS_TR_NONE,
			      ESYS_TR_NONE, ESYS_TR_NONE, &esysh);

	return esysh;
}

static inline int
tpm2_handle_mso(TSS_CONTEXT *tssContext, TPM_HANDLE esysh, UINT32 mso)
{
	return (tpm2_handle_ext(tssContext, esysh) >> 24) == mso;
}
