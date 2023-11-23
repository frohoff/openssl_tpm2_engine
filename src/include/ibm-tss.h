#define TSSINCLUDE(x) < TSS_INCLUDE/x >
#include TSSINCLUDE(tss.h)
#include TSSINCLUDE(tssresponsecode.h)
#include TSSINCLUDE(tssutils.h)
#include TSSINCLUDE(tssmarshal.h)
#include TSSINCLUDE(Unmarshal_fp.h)
#include TSSINCLUDE(tsscrypto.h)
#include TSSINCLUDE(tsscryptoh.h)

#define EXT_TPM_RH_OWNER	TPM_RH_OWNER
#define EXT_TPM_RH_PLATFORM	TPM_RH_PLATFORM
#define EXT_TPM_RH_ENDORSEMENT	TPM_RH_ENDORSEMENT
#define EXT_TPM_RH_NULL		TPM_RH_NULL
#define INT_TPM_RH_NULL		TPM_RH_NULL

#define VAL(X)			X.val
#define VAL_2B(X, MEMBER)	X.b.MEMBER
#define VAL_2B_P(X, MEMBER)	X->b.MEMBER

static inline void
tpm2_error(TPM_RC rc, const char *reason)
{
	const char *msg, *submsg, *num;

	fprintf(stderr, "%s failed with %d\n", reason, rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	fprintf(stderr, "%s%s%s\n", msg, submsg, num);
}


static inline TPM_RC
tpm2_GetCapability(TSS_CONTEXT *tssContext, TPM_CAP capability,
		   UINT32 property, UINT32 propertyCount,
		   TPMI_YES_NO *moreData, TPMS_CAPABILITY_DATA *capabilityData)
{
	GetCapability_In in;
	GetCapability_Out out;
	TPM_RC rc;

	in.capability = capability;
	in.property = property;
	in.propertyCount = propertyCount;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);

	if (moreData)
		*moreData = out.moreData;
	if (capabilityData)
		*capabilityData = out.capabilityData;

	return rc;
}

static inline TPM_RC
tpm2_Import(TSS_CONTEXT *tssContext, TPM_HANDLE parentHandle,
	    DATA_2B *encryptionKey, TPM2B_PUBLIC *objectPublic,
	    PRIVATE_2B *duplicate, ENCRYPTED_SECRET_2B *inSymSeed,
	    TPMT_SYM_DEF_OBJECT *symmetricAlg, PRIVATE_2B *outPrivate,
	    TPM_HANDLE auth, const char *authVal)
{
	Import_In iin;
	Import_Out iout;
	TPM_RC rc;

	iin.parentHandle = parentHandle;
	iin.encryptionKey.t = *encryptionKey;
	iin.objectPublic = *objectPublic;
	iin.duplicate.t = *duplicate;
	iin.inSymSeed.t = *inSymSeed;
	iin.symmetricAlg = *symmetricAlg;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&iout,
			 (COMMAND_PARAMETERS *)&iin,
			 NULL,
			 TPM_CC_Import,
			 auth, authVal, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);

	*outPrivate = iout.outPrivate.t;

	return rc;
}

static inline TPM_RC
tpm2_Create(TSS_CONTEXT *tssContext, TPM_HANDLE parentHandle,
	    TPM2B_SENSITIVE_CREATE *inSensitive, TPM2B_PUBLIC *inPublic,
	    PRIVATE_2B *outPrivate, TPM2B_PUBLIC *outPublic,
	    TPM_HANDLE auth, const char *authVal)
{
	Create_In cin;
	Create_Out cout;
	TPM_RC rc;

	cin.parentHandle = parentHandle;
	cin.inSensitive = *inSensitive;
	cin.inPublic = *inPublic;
	cin.outsideInfo.t.size = 0;
	cin.creationPCR.count = 0;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&cout,
			 (COMMAND_PARAMETERS *)&cin,
			 NULL,
			 TPM_CC_Create,
			 auth, authVal, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);

	*outPrivate = cout.outPrivate.t;
	*outPublic = cout.outPublic;

	return rc;
}

static inline TPM_RC
tpm2_Unseal(TSS_CONTEXT *tssContext, TPM_HANDLE itemHandle,
	    SENSITIVE_DATA_2B *outData, TPM_HANDLE auth,
	    const char *authVal)
{
	Unseal_In uin;
	Unseal_Out uout;
	TPM_RC rc;

	uin.itemHandle = itemHandle;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&uout,
			 (COMMAND_PARAMETERS *)&uin,
			 NULL,
			 TPM_CC_Unseal,
			 auth, authVal, TPMA_SESSION_ENCRYPT,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_EvictControl(TSS_CONTEXT *tssContext, TPM_HANDLE objectHandle,
		  TPM_HANDLE persistentHandle)
{
	EvictControl_In ein;
	TPM_RC rc;

	ein.auth = TPM_RH_OWNER;
	ein.objectHandle = objectHandle;
	ein.persistentHandle = persistentHandle;

	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&ein,
			 NULL,
			 TPM_CC_EvictControl,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_ReadPublic(TSS_CONTEXT *tssContext, TPM_HANDLE objectHandle,
		TPMT_PUBLIC *pub, TPM_HANDLE auth)
{
	ReadPublic_In rin;
	ReadPublic_Out rout;
	TPM_RC rc;
	UINT32 flags = 0;

	if (auth != TPM_RH_NULL)
		flags = TPMA_SESSION_ENCRYPT;

	rin.objectHandle = objectHandle;

	rc = TSS_Execute (tssContext,
			  (RESPONSE_PARAMETERS *)&rout,
			  (COMMAND_PARAMETERS *)&rin,
			  NULL,
			  TPM_CC_ReadPublic,
			  auth, NULL, flags,
			  TPM_RH_NULL, NULL, 0);

	if (rc) {
		tpm2_error(rc, "TPM2_ReadPublic");
		return rc;
	}

	if (pub)
		*pub = rout.outPublic.publicArea;

	return rc;
}

static inline TPM_RC
tpm2_RSA_Decrypt(TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle,
		 PUBLIC_KEY_RSA_2B *cipherText, TPMT_RSA_DECRYPT *inScheme,
		 PUBLIC_KEY_RSA_2B *message,
		 TPM_HANDLE auth, const char *authVal, int flags)
{
	RSA_Decrypt_In in;
	RSA_Decrypt_Out out;
	TPM_RC rc;

	in.keyHandle = keyHandle;
	in.inScheme = *inScheme;
	in.cipherText.t = *cipherText;
	in.label.t.size = 0;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_RSA_Decrypt,
			 auth, authVal, flags,
			 TPM_RH_NULL, NULL, 0);

	*message = out.message.t;

	return rc;
}

static inline TPM_RC
tpm2_Sign(TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle, DIGEST_2B *digest,
	  TPMT_SIG_SCHEME *inScheme, TPMT_SIGNATURE *signature,
	  TPM_HANDLE auth, const char *authVal)
{
	Sign_In in;
	Sign_Out out;
	TPM_RC rc;

	in.keyHandle = keyHandle;
	in.digest.t = *digest;
	in.inScheme = *inScheme;
	in.validation.tag = TPM_ST_HASHCHECK;
	in.validation.hierarchy = TPM_RH_NULL;
	in.validation.digest.t.size = 0;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Sign,
			 auth, authVal, 0,
			 TPM_RH_NULL, NULL, 0);

	*signature = out.signature;

	return rc;
}

static inline TPM_RC
tpm2_ECDH_ZGen(TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle,
	       const TPM2B_ECC_POINT *inPoint, TPM2B_ECC_POINT *outPoint,
	       TPM_HANDLE auth, const char *authVal)
{
	ECDH_ZGen_In in;
	ECDH_ZGen_Out out;
	TPM_RC rc;

	in.keyHandle = keyHandle;
	in.inPoint = *inPoint;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ECDH_ZGen,
			 auth, authVal, TPMA_SESSION_ENCRYPT,
			 TPM_RH_NULL, NULL, 0);

	*outPoint = out.outPoint;

	return rc;
}

static inline TPM_RC
tpm2_CreatePrimary(TSS_CONTEXT *tssContext, TPM_HANDLE primaryHandle,
		   TPM2B_SENSITIVE_CREATE *inSensitive,
		   TPM2B_PUBLIC *inPublic, TPM_HANDLE *objectHandle,
		   TPM2B_PUBLIC *outPublic,
		   TPM_HANDLE auth, const char *authVal)
{
	CreatePrimary_In in;
	CreatePrimary_Out out;
	TPM_RC rc;

	in.primaryHandle = primaryHandle;
	in.inSensitive = *inSensitive;
	in.inPublic = *inPublic;
	/* no outside info */
	in.outsideInfo.t.size = 0;
	/* no PCR state */
	in.creationPCR.count = 0;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 auth, authVal, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);

	*objectHandle = out.objectHandle;
	if (outPublic)
		*outPublic = out.outPublic;

	return rc;
}

static inline TPM_RC
tpm2_FlushContext(TSS_CONTEXT *tssContext, TPM_HANDLE flushHandle)
{
	FlushContext_In in;
	TPM_RC rc;

	in.flushHandle = flushHandle;

	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_ECC_Parameters(TSS_CONTEXT *tssContext, TPMI_ECC_CURVE curveID,
		    TPMS_ALGORITHM_DETAIL_ECC *parameters)
{
	ECC_Parameters_In in;
	ECC_Parameters_Out out;
	TPM_RC rc;

	in.curveID = curveID;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ECC_Parameters,
			 TPM_RH_NULL, NULL, 0);

	if (parameters)
		*parameters = out.parameters;

	return rc;
}

static inline TPM_RC
tpm2_StartAuthSession(TSS_CONTEXT *tssContext, TPM_HANDLE tpmKey,
		      TPM_HANDLE bind, TPM_SE sessionType,
		      TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash,
		      TPM_HANDLE *sessionHandle,
		      const char *bindPassword)
{
	StartAuthSession_In in;
	StartAuthSession_Out out;
	StartAuthSession_Extra extra;
	TPM_RC rc;

	memset(&in, 0, sizeof(in));
	memset(&extra, 0 , sizeof(extra));

	extra.bindPassword = bindPassword;

	in.tpmKey = tpmKey;
	in.bind = bind;
	in.sessionType = sessionType;
	in.symmetric = *symmetric;
	in.authHash = authHash;

	if (tpmKey != TPM_RH_NULL) {
		/* For the TSS to use a key as salt, it must have
		 * access to the public part.  It does this by keeping
		 * key files, but request the public part just to make
		 * sure*/
		tpm2_ReadPublic(tssContext, tpmKey,  NULL, TPM_RH_NULL);
		/* don't care what rout returns, the purpose of the
		 * operation was to get the public key parameters into
		 * the tss so it can construct the salt */
	}

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 (EXTRA_PARAMETERS *)&extra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);

	*sessionHandle = out.sessionHandle;

	return rc;
}

static inline TPM_RC
tpm2_LoadExternal(TSS_CONTEXT *tssContext, TPM2B_SENSITIVE *inPrivate,
		  TPM2B_PUBLIC *inPublic, TPM_HANDLE hierarchy,
		  TPM_HANDLE *objectHandle, NAME_2B *name)
{
	LoadExternal_In in;
	LoadExternal_Out out;
	TPM_RC rc;

	if (inPrivate)
		in.inPrivate = *inPrivate;
	else
		in.inPrivate.t.size = 0;
	in.inPublic = *inPublic;
	in.hierarchy = hierarchy;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_LoadExternal,
			 TPM_RH_NULL, NULL, 0);

	*objectHandle = out.objectHandle;
	if (name)
		*name = out.name.t;

	return rc;
}

static inline TPM_RC
tpm2_VerifySignature(TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle,
		     DIGEST_2B *digest, TPMT_SIGNATURE *signature,
		     TPMT_TK_VERIFIED *validation)
{
	VerifySignature_In in;
	VerifySignature_Out out;
	TPM_RC rc;

	in.keyHandle = keyHandle;
	in.digest.t = *digest;
	in.signature = *signature;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_VerifySignature,
			 TPM_RH_NULL, NULL, 0);

	if (validation)
		*validation = out.validation;

	return rc;
}

static inline TPM_RC
tpm2_Load(TSS_CONTEXT *tssContext, TPM_HANDLE parentHandle,
	  PRIVATE_2B *inPrivate, const TPM2B_PUBLIC *inPublic,
	  TPM_HANDLE *objectHandle,
	  TPM_HANDLE auth, const char *authVal)
{
	Load_In in;
	Load_Out out;
	TPM_RC rc;

	in.parentHandle = parentHandle;
	in.inPrivate.t = *inPrivate;
	in.inPublic = *inPublic;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 auth, authVal, 0,
			 TPM_RH_NULL, NULL, 0);

	if (rc == TPM_RC_SUCCESS)
		*objectHandle = out.objectHandle;

	return rc;
}

static inline TPM_RC
tpm2_PolicyPCR(TSS_CONTEXT *tssContext, TPM_HANDLE policySession,
	       DIGEST_2B *pcrDigest, TPML_PCR_SELECTION *pcrs)
{
	PolicyPCR_In in;
	TPM_RC rc;

	in.policySession = policySession;
	in.pcrDigest.t = *pcrDigest;
	in.pcrs = *pcrs;

	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyPCR,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_PolicyAuthorize(TSS_CONTEXT *tssContext, TPM_HANDLE policySession,
		     DIGEST_2B *approvedPolicy, DIGEST_2B *policyRef,
		     NAME_2B *keySign, TPMT_TK_VERIFIED *checkTicket)
{
	PolicyAuthorize_In in;
	TPM_RC rc;

	in.policySession = policySession;
	in.approvedPolicy.t = *approvedPolicy;
	in.policyRef.t = *policyRef;
	in.keySign.t = *keySign;
	in.checkTicket = *checkTicket;

	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyAuthorize,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_PolicyAuthValue(TSS_CONTEXT *tssContext, TPM_HANDLE policySession)
{
	PolicyAuthValue_In in;
	TPM_RC rc;

	in.policySession = policySession;

	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyAuthValue,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_PolicyCounterTimer(TSS_CONTEXT *tssContext, TPM_HANDLE policySession,
			DIGEST_2B *operandB, UINT16 offset,
			TPM_EO operation)
{
	PolicyCounterTimer_In in;
	TPM_RC rc;

	in.policySession = policySession;
	in.operandB.t = *operandB;
	in.offset = offset;
	in.operation = operation;

	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyCounterTimer,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_PolicyRestart(TSS_CONTEXT *tssContext, TPM_HANDLE sessionHandle)
{
	PolicyRestart_In in;
	TPM_RC rc;

	in.sessionHandle = sessionHandle;

	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyRestart,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_PolicyLocality(TSS_CONTEXT *tssContext, TPM_HANDLE policySession,
		    UINT8 locality)
{
	PolicyLocality_In in;
	TPM_RC rc;

	in.policySession = policySession;
	in.locality.val = locality;

	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyLocality,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}

static inline TPM_RC
tpm2_PolicyGetDigest(TSS_CONTEXT *tssContext, TPM_HANDLE policySession,
		     DIGEST_2B *digest)
{
	PolicyGetDigest_In in;
	PolicyGetDigest_Out out;
	TPM_RC rc;

	in.policySession = policySession;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PolicyGetDigest,
			 TPM_RH_NULL, NULL, 0);

	*digest = out.policyDigest.t;

	return rc;
}

static inline TPM_RC
tpm2_PCR_Read(TSS_CONTEXT *tssContext, TPML_PCR_SELECTION *pcrSelectionIn,
	      TPML_PCR_SELECTION *pcrSelectionOut, TPML_DIGEST *pcrValues)
{
	PCR_Read_In in;
	PCR_Read_Out out;
	TPM_RC rc;

	in.pcrSelectionIn = *pcrSelectionIn;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_PCR_Read,
			 TPM_RH_NULL, NULL, 0);

	if (rc)
		return rc;

	*pcrSelectionOut = out.pcrSelectionOut;
	*pcrValues = out.pcrValues;

	return rc;
}

static inline TPM_HANDLE
tpm2_handle_int(TSS_CONTEXT *tssContext, TPM_HANDLE h)
{
	return h;
}

static inline TPM_HANDLE
tpm2_handle_ext(TSS_CONTEXT *tssContext, TPM_HANDLE h)
{
	return h;
}

static inline int
tpm2_handle_mso(TSS_CONTEXT *tssContext, TPM_HANDLE h, UINT32 mso)
{
	return (h >> 24) == mso;
}
