/* Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Note: The ASN.1 defines constitute an interface specification for
 * the openssl key format which may be copied by other implementations
 * as fair use regardless of licence
 */
#ifndef _TPM2_ASN_H
#define _TPM2_ASN_H

#include <openssl/asn1t.h>
#include <openssl/pem.h>

/*
 * Define the format of policy commands required for TPM enhanced authorization.
 *
 * TPMPolicy ::= SEQUENCE {
 *	CommandCode		[0] EXPLICIT INTEGER
 *	CommandPolicy		[1] EXPLICIT OCTET STRING
 * }
 */
typedef struct {
	ASN1_INTEGER *CommandCode;
	ASN1_OCTET_STRING *CommandPolicy;
} TSSOPTPOLICY;

#if OPENSSL_VERSION_NUMBER < 0x10100000
DECLARE_STACK_OF(TSSOPTPOLICY);
#define sk_TSSOPTPOLICY_new_null() SKM_sk_new_null(TSSOPTPOLICY)
#define sk_TSSOPTPOLICY_push(sk, policy) SKM_sk_push(TSSOPTPOLICY, sk, policy)
#define sk_TSSOPTPOLICY_pop(sk) SKM_sk_pop(TSSOPTPOLICY, sk)
#define sk_TSSOPTPOLICY_free(sk) SKM_sk_free(TSSOPTPOLICY, sk)
#define sk_TSSOPTPOLICY_num(policy) SKM_sk_num(TSSOPTPOLICY, policy)
#define sk_TSSOPTPOLICY_value(policy, i) SKM_sk_value(TSSOPTPOLICY, policy, i)
#else
DEFINE_STACK_OF(TSSOPTPOLICY);
#endif

/*
 * Define the format of optional authorization policy.  The policy for
 * the key must begin with a TPM2_PolicyAuthorize statement with a
 * nonce and pub key but empty signature.  Each element of the
 * AuthPolicy->Policy array must end with TPM2_PolicyAuthorize with
 * empty nonce and pubkey but polulated signature which is a hash of
 * nonce || this policy
 *
 * TPMAuthPolicy ::= {
 *      Name                  [0] EXPLICIT UTF8STRING OPTIONAL
 *      Policy                [1] EXPLICIT SEQUENCE OF TPMPolicy
 * }
 */
typedef struct {
	ASN1_STRING *name;
	STACK_OF(TSSOPTPOLICY) *policy;
} TSSAUTHPOLICY;

#if OPENSSL_VERSION_NUMBER < 0x10100000
DECLARE_STACK_OF(TSSAUTHPOLICY);
#define sk_TSSAUTHPOLICY_new_null() SKM_sk_new_null(TSSAUTHPOLICY)
#define sk_TSSAUTHPOLICY_push(sk, policy) SKM_sk_push(TSSAUTHPOLICY, sk, policy)
#define sk_TSSAUTHPOLICY_pop(sk) SKM_sk_pop(TSSAUTHPOLICY, sk)
#define sk_TSSAUTHPOLICY_free(sk) SKM_sk_free(TSSAUTHPOLICY, sk)
#define sk_TSSAUTHPOLICY_num(policy) SKM_sk_num(TSSAUTHPOLICY, policy)
#define sk_TSSAUTHPOLICY_value(policy, i) SKM_sk_value(TSSAUTHPOLICY, policy, i)
#else
DEFINE_STACK_OF(TSSAUTHPOLICY);
#endif

/*
 * Define the format of a TPM key file.  The current format covers
 * both TPM1.2 keys as well as symmetrically encrypted private keys
 * produced by TSS2_Import and the TPM2 format public key which
 * contains things like the policy but which is cryptographically tied
 * to the private key.
 *
 * OldTPMKey ::= SEQUENCE {
 *	type		OBJECT IDENTIFIER
 *	emptyAuth	[0] EXPLICIT BOOLEAN OPTIONAL
 *	parent		[1] EXPLICIT INTEGER OPTIONAL
 *	pubkey		[2] EXPLICIT OCTET STRING OPTIONAL
 *	policy		[3] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL
 *	privkey		OCTET STRING
 * }
 *
 * This is the newer form of the key file.  It no-longer covers TPM
 * 1.2 keys and thus the parent and pubkey are no-longer optional
 *
 * TPMKey ::= SEQUENCE {
 *	type		OBJECT IDENTIFIER
 *	emptyAuth	[0] EXPLICIT BOOLEAN OPTIONAL
 *	policy		[1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL
 *	secret		[2] EXPLICIT OCTET STRING OPTIONAL
 *	authPolicy	[3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL
 *	parent		INTEGER
 *	pubkey		OCTET STRING
 *	privkey		OCTET STRING
 * }
 */

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	STACK_OF(TSSOPTPOLICY) *policy;
	ASN1_OCTET_STRING *privkey;
} TSSLOADABLE;

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	STACK_OF(TSSOPTPOLICY) *policy;
	ASN1_OCTET_STRING *secret;
	STACK_OF(TSSAUTHPOLICY) *authPolicy;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY;

/* the two type oids are in the TCG namespace 2.23.133; we choose an
 *  unoccupied child (10) for keytype file and two values:
 *    1 : Key that is directly loadable
 *    2 : Key that must first be imported then loaded
 *
 * the TCG actually gave us some OIDs which turn out to be different
 * from the ones we chose, so keep OID_Oldloadablekey for backwards
 * compatibility, but add the new loadable and importable key types on
 * the new OIDs
 */
#define OID_OldloadableKey		"2.23.133.10.2"

#define OID_loadableKey			"2.23.133.10.1.3"
#define OID_importableKey		"2.23.133.10.1.4"
#define OID_sealedData			"2.23.133.10.1.5"

/* This is the PEM guard tag */
#define TSSLOADABLE_PEM_STRING "TSS2 KEY BLOB"
#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

DECLARE_ASN1_FUNCTIONS(TSSOPTPOLICY);
DECLARE_ASN1_FUNCTIONS(TSSAUTHPOLICY);
DECLARE_ASN1_FUNCTIONS(TSSLOADABLE);
DECLARE_ASN1_FUNCTIONS(TSSPRIVKEY);
DECLARE_PEM_write_bio(TSSLOADABLE, TSSLOADABLE);
DECLARE_PEM_read_bio(TSSLOADABLE, TSSLOADABLE);
DECLARE_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY);
DECLARE_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY);

#endif
