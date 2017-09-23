/* Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * GPLv2
 */
#ifndef _TPM2_ASN_H
#define _TPM2_ASN_H

#include <openssl/asn1t.h>

/*
 * Define the format of a TPM key file.  The current format covers
 * both TPM1.2 keys as well as symmetrically encrypted private keys
 * produced by TSS2_Import and the TPM2 format public key which
 * contains things like the policy but which is cryptographically tied
 * to the private key.
 *
 * TPMKey ::= SEQUENCE {
 *	type		OBJECT IDENTIFIER
 *	emptyAuth	[0] EXPLICIT BOOLEAN OPTIONAL
 *	parent		[1] EXPLICIT INTEGER OPTIONAL
 *	pubkey		[2] EXPLICIT OCTET STRING OPTIONAL
 *	privkey		OCTET STRING
 * }
 */

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	ASN1_OCTET_STRING *privkey;
} TSSLOADABLE;

/* the two type oids are in the TCG namespace 2.23.133; we choose an
 *  unoccupied child (10) for keytype file and two values:
 *    1 : Key that is directly loadable
 *    2 : Key that must first be imported then loaded
 */
#define OID_12Key		"2.23.133.10.1"
#define OID_loadableKey		"2.23.133.10.2"
#define OID_importableKey	"2.23.133.10.3"

ASN1_SEQUENCE(TSSLOADABLE) = {
	ASN1_SIMPLE(TSSLOADABLE, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSLOADABLE, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_EXP_OPT(TSSLOADABLE, parent, ASN1_INTEGER, 1),
	ASN1_EXP_OPT(TSSLOADABLE, pubkey, ASN1_OCTET_STRING, 2),
	ASN1_SIMPLE(TSSLOADABLE, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSLOADABLE)

IMPLEMENT_ASN1_FUNCTIONS(TSSLOADABLE);

/* This is the PEM guard tag */
#define TSSLOADABLE_PEM_STRING "TSS2 KEY BLOB"

static IMPLEMENT_PEM_write_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE)
static IMPLEMENT_PEM_read_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE)

#endif
