/*
 *
 *   Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 *   SPDX-License-Identifier: LGPL-2.1-only
 */


#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#define TSSINCLUDE(x) < TSS_INCLUDE/x >
#include TSSINCLUDE(tss.h)
#include TSSINCLUDE(tssutils.h)
#include TSSINCLUDE(tssmarshal.h)
#include TSSINCLUDE(Unmarshal_fp.h)
#include TSSINCLUDE(tsscrypto.h)
#include TSSINCLUDE(tsscryptoh.h)

#include "tpm2-asn.h"
#include "tpm2-common.h"

#define OPT_DEPRECATED 0x1ff
#define OPT_RESTRICTED 0x1fe

static struct option long_options[] = {
	{"auth", 0, 0, 'a'},
	{"auth-parent", 1, 0, 'b'},
	{"help", 0, 0, 'h'},
	{"key-size", 1, 0, 's'},
	{"name-scheme", 1, 0, 'n'},
	{"parent-handle", 1, 0, 'p'},
	{"wrap", 1, 0, 'w'},
	{"version", 0, 0, 'v'},
	{"password", 1, 0, 'k'},
	{"rsa", 0, 0, 'r'},
	{"ecc", 1, 0, 'e'},
	{"list-curves", 0, 0, 'l'},
	{"da", 0, 0, 'd'},
	{"key-policy", 1, 0, 'c'},
	{"import", 1, 0, 'i'},
	{"restricted", 0, 0, OPT_RESTRICTED},
	/*
	 * The option --deprecated allows us to create old format keys
	 * for the purposes of testing.  It should never be used in
	 * the field so is an undocumented option
	 */
	{"deprecated", 0, 0, OPT_DEPRECATED},
	{0, 0, 0, 0}
};

static TPM_ALG_ID name_alg = TPM_ALG_SHA256;

void
usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-a, --auth                    require a password for the key [NO]\n"
		"\t-b, --auth-parent <pwd>       Specify the parent key password\n"
		"\t                              (default EmptyAuth)\n"
		"\t-d, --da                      mark the key as having Dictionary Attack implications.  This means that if\n"
		"\t                              the key password is incorrectly presented too many times, the TPM may\n"
		"\t                              Implement DA mitigation and refuse connections for a while\n"
		"\t-h, --help                    print this help message\n"
		"\t-s, --key-size <size>         key size in bits [2048]\n"
		"\t-n, --name-scheme <scheme>    name algorithm to use sha1 [sha256] sha384 sha512\n"
		"\t-p, --parent-handle <handle>  parent for the key, can either be a\n"
		"\t                              persistent key or a hierarchy.\n"
		"\t                              the hierarchies can be 'platform',\n"
		"\t                              'owner', 'null' or 'endorsement'.\n"
		"\t                              The seeds used for derivation are\n"
		"\t                              platform, storage, null or endorsement\n"
		"\t                              respectively\n"
		"\t-v, --version                 print package version\n"
		"\t-w, --wrap <file>             wrap an existing openssl PEM key. <file> can\n"
		"                                be in either PKCS12 or OpenSSL standard PEM\n"
		"                                private key form (PKCS1 or PKCS8)\n"
		"\t-k, --password <pwd>          use this password instead of prompting\n"
		"\t-r, --rsa                     create an RSA key (the default)\n"
		"\t-e, --ecc <curve>             Create an ECC key using the specified curve.\n"
		"\t                              Supported curves are bnp256, nisp256, nisp384\n"
		"\t-l, --list-curves             List all the Elliptic Curves the TPM supports\n"
		"\t-c, --key-policy              Specify a policy for the TPM key\n"
		"\t-i, --import <pubkey>         Create an importable key with the outer\n"
		"                                wrapper encrypted to <pubkey>\n"
		"\t--restricted                  Create a restricted key.  A restricted key\n"
		"                                may not be used for general signing or\n"
		"                                decryption but may be the parent of other\n"
		"                                keys (i.e. it is a storage key)\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

void
openssl_print_errors()
{
	ERR_load_ERR_strings();
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
}

TPM_RC tpm2_ObjectPublic_GetName(TPM2B_NAME *name,
				 TPMT_PUBLIC *tpmtPublic)
{
	TPM_RC rc = 0;
	uint16_t written = 0;
	TPMT_HA digest;
	uint32_t sizeInBytes;
	uint8_t buffer[MAX_RESPONSE_SIZE];

	/* marshal the TPMT_PUBLIC */
	if (rc == 0) {
		INT32 size = MAX_RESPONSE_SIZE;
		uint8_t *buffer1 = buffer;
		rc = TSS_TPMT_PUBLIC_Marshal(tpmtPublic, &written, &buffer1, &size);
	}
	/* hash the public area */
	if (rc == 0) {
		sizeInBytes = TSS_GetDigestSize(tpmtPublic->nameAlg);
		digest.hashAlg = tpmtPublic->nameAlg;	/* Name digest algorithm */
		/* generate the TPMT_HA */
		rc = TSS_Hash_Generate(&digest,
				       written, buffer,
				       0, NULL);
	}
	if (rc == 0) {
		/* copy the digest */
		memcpy(name->t.name + sizeof(TPMI_ALG_HASH), (uint8_t *)&digest.digest, sizeInBytes);
		/* copy the hash algorithm */
		TPMI_ALG_HASH nameAlgNbo = htons(tpmtPublic->nameAlg);
		memcpy(name->t.name, (uint8_t *)&nameAlgNbo, sizeof(TPMI_ALG_HASH));
		/* set the size */
		name->t.size = sizeInBytes + sizeof(TPMI_ALG_HASH);
	}
	return rc;
}

/*
 * Cut down version of Part 4 Supporting Routines 7.6.3.10
 *
 * Hard coded to symmetrically encrypt with aes128 as the inner
 * wrapper and no outer wrapper but with a prototype that allows
 * drop in replacement with a tss equivalent
 */
TPM_RC tpm2_innerwrap(TPMT_SENSITIVE *s,
		      TPMT_PUBLIC *pub,
		      TPMT_SYM_DEF_OBJECT *symdef,
		      TPM2B_DATA *innerkey,
		      TPM2B_PRIVATE *p)
{
	BYTE *buf = p->t.buffer;

	p->t.size = 0;
	memset(p, 0, sizeof(*p));

	/* hard code AES CFB */
	if (symdef->algorithm == TPM_ALG_AES
	    && symdef->mode.aes == TPM_ALG_CFB) {
		TPMT_HA hash;
		const TPM_ALG_ID nalg = pub->nameAlg;
		const int hlen = TSS_GetDigestSize(nalg);
		TPM2B *digest = (TPM2B *)buf;
		TPM2B *s2b;
		int32_t size;
		unsigned char null_iv[AES_128_BLOCK_SIZE_BYTES];
		UINT16 bsize, written = 0;
		TPM2B_NAME name;

		/* WARNING: don't use the static null_iv trick here:
		 * the AES routines alter the passed in iv */
		memset(null_iv, 0, sizeof(null_iv));

		/* reserve space for hash before the encrypted sensitive */
		bsize = sizeof(digest->size) + hlen;
		buf += bsize;
		p->t.size += bsize;
		s2b = (TPM2B *)buf;

		/* marshal the digest size */
		buf = (BYTE *)&digest->size;
		bsize = hlen;
		size = 2;
		TSS_UINT16_Marshal(&bsize, &written, &buf, &size);

		/* marshal the unencrypted sensitive in place */
		size = sizeof(*s);
		bsize = 0;
		buf = s2b->buffer;
		TSS_TPMT_SENSITIVE_Marshal(s, &bsize, &buf, &size);
		buf = (BYTE *)&s2b->size;
		size = 2;
		TSS_UINT16_Marshal(&bsize, &written, &buf, &size);

		bsize = bsize + sizeof(s2b->size);
		p->t.size += bsize;

		tpm2_ObjectPublic_GetName(&name, pub);
		/* compute hash of unencrypted marshalled sensitive and
		 * write to the digest buffer */
		hash.hashAlg = nalg;
		TSS_Hash_Generate(&hash, bsize, s2b,
				  name.t.size, name.t.name,
				  0, NULL);
		memcpy(digest->buffer, &hash.digest, hlen);

		/* encrypt hash and sensitive in place */
		TSS_AES_EncryptCFB(p->t.buffer,
				   symdef->keyBits.aes,
				   innerkey->b.buffer,
				   null_iv,
				   p->t.size,
				   p->t.buffer);
	} else if (symdef->algorithm == TPM_ALG_NULL) {
		TPM2B *s2b = (TPM2B *)buf;
		int32_t size = sizeof(*s);
		UINT16 bsize = 0, written = 0;

		buf = s2b->buffer;

		/* marshal the unencrypted sensitive in place */
		TSS_TPMT_SENSITIVE_Marshal(s, &bsize, &buf, &size);
		buf = (BYTE *)&s2b->size;
		size = 2;
		TSS_UINT16_Marshal(&bsize, &written, &buf, &size);

		p->b.size += bsize + sizeof(s2b->size);
	} else {
		printf("Unknown symmetric algorithm\n");
		return TPM_RC_SYMMETRIC;
	}

	return TPM_RC_SUCCESS;
}

TPM_RC tpm2_outerwrap(EVP_PKEY *parent,
		      TPMT_SENSITIVE *s,
		      TPMT_PUBLIC *pub,
		      TPM2B_PRIVATE *p,
		      TPM2B_ENCRYPTED_SECRET *enc_secret)
{
	TPM2B_PRIVATE secret, seed;
	/*  amount of room in the buffer for the integrity TPM2B */
	const int name_alg_size = TSS_GetDigestSize(pub->nameAlg);
	const int integrity_skip = name_alg_size + 2;
	//	BYTE *integrity = p->t.buffer;
	BYTE *sensitive = p->t.buffer + integrity_skip;
	BYTE *buf;
	TPM2B *t2b;
	INT32 size;
	size_t ssize;
	UINT16 bsize, written = 0;
	EVP_PKEY *ephemeral = NULL;
	EVP_PKEY_CTX *ctx;
	TPM2B_ECC_POINT pub_pt, ephemeral_pt;
	EC_KEY *e_parent, *e_ephemeral;
	const EC_GROUP *group;
	unsigned char aeskey[T2_AES_KEY_BYTES];
	/* hmac follows namealg, so set to max size */
	TPM2B_KEY hmackey;
	TPMT_HA hmac;
	TPM2B_NAME name;
	TPM2B_DIGEST digest;
	unsigned char null_iv[AES_128_BLOCK_SIZE_BYTES];
	TPM2B null_2b;

	null_2b.size = 0;

	if (EVP_PKEY_type(EVP_PKEY_id(parent)) != EVP_PKEY_EC) {
		printf("Can only currently wrap to EC parent\n");
		return TPM_RC_ASYMMETRIC;
	}

	e_parent = EVP_PKEY_get1_EC_KEY(parent);
	group = EC_KEY_get0_group(e_parent);

	/* marshal the sensitive into a TPM2B */
	t2b = (TPM2B *)sensitive;
	buf = t2b->buffer;
	size = sizeof(p->t.buffer) - integrity_skip;
	bsize = 0;
	TSS_TPMT_SENSITIVE_Marshal(s, &bsize, &buf, &size);
	buf = (BYTE *)&t2b->size;
	size = 2;
	TSS_UINT16_Marshal(&bsize, &written, &buf, &size);
	/* set the total size of the private entity */
	p->b.size = bsize + sizeof(UINT16) + integrity_skip;

	/* compute the elliptic curve shared (and encrypted) secret */
	ctx = EVP_PKEY_CTX_new(parent, NULL);
	if (!ctx)
		goto openssl_err;
	if (EVP_PKEY_keygen_init(ctx) != 1)
		goto openssl_err;
	EVP_PKEY_keygen(ctx, &ephemeral);
	if (!ephemeral)
		goto openssl_err;
	/* otherwise the ctx free will free the key */
#if OPENSSL_VERSION_NUMBER < 0x10100000
	CRYPTO_add(&ephemeral->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else
	EVP_PKEY_up_ref(ephemeral);
#endif
	EVP_PKEY_CTX_free(ctx);

	e_ephemeral = EVP_PKEY_get1_EC_KEY(ephemeral);

	/* now begin again with the ephemeral private key because the
	 * context must be initialised with the private key */
	ctx = EVP_PKEY_CTX_new(ephemeral, NULL);
	if (!ctx)
		goto openssl_err;
	if (EVP_PKEY_derive_init(ctx) != 1)
		goto openssl_err;
	if (EVP_PKEY_derive_set_peer(ctx, parent) != 1)
		goto openssl_err;
	ssize = sizeof(secret.t.buffer);
	if (EVP_PKEY_derive(ctx, secret.b.buffer, &ssize) != 1)
		goto openssl_err;
	secret.b.size = ssize;
	EVP_PKEY_CTX_free(ctx);

	tpm2_get_public_point(&pub_pt, group, EC_KEY_get0_public_key(e_parent));
	tpm2_get_public_point(&ephemeral_pt, group,
			      EC_KEY_get0_public_key(e_ephemeral));
	EC_KEY_free(e_parent);
	EC_KEY_free(e_ephemeral);

	/* now pass the secret through KDFe to get the shared secret
	 * The size is the size of the parent name algorithm which we
	 * assume to be sha256 */
	TSS_KDFE(seed.b.buffer, pub->nameAlg, &secret.b, "DUPLICATE",
		 &ephemeral_pt.point.x.b, &pub_pt.point.x.b,
		 SHA256_DIGEST_LENGTH*8);
	seed.b.size = SHA256_DIGEST_LENGTH;

	/* and finally through KDFa to get the aes symmetric encryption key */
	tpm2_ObjectPublic_GetName(&name, pub);
	TSS_KDFA(aeskey, pub->nameAlg, &seed.b, "STORAGE", &name.b, &null_2b,
		 T2_AES_KEY_BITS);
	/* and then the outer HMAC key */
	hmackey.b.size = name_alg_size;
	TSS_KDFA(hmackey.b.buffer, pub->nameAlg, &seed.b, "INTEGRITY",
		 &null_2b, &null_2b, name_alg_size * 8);
	/* OK the ephermeral public point is now the encrypted secret */
	size = sizeof(ephemeral_pt);
	buf = enc_secret->b.buffer;
	TSS_TPM2B_ECC_POINT_Marshal(&ephemeral_pt, &written,
				    &buf, &size);
	enc_secret->b.size = written;
	memset(null_iv, 0, sizeof(null_iv));
	TSS_AES_EncryptCFB(sensitive, T2_AES_KEY_BITS, aeskey, null_iv,
			   p->t.size - integrity_skip, sensitive);
	hmac.hashAlg = pub->nameAlg;
	TSS_HMAC_Generate(&hmac, &hmackey,
			  p->t.size - integrity_skip, sensitive,
			  name.b.size, name.b.buffer,
			  0, NULL);
	digest.b.size  = name_alg_size;
	memcpy(digest.b.buffer, &hmac.digest, digest.b.size);
	size = integrity_skip;
	buf = p->t.buffer;
	TSS_TPM2B_DIGEST_Marshal(&digest, &written, &buf, &size);
	return TPM_RC_SUCCESS;

 openssl_err:
	ERR_print_errors_fp(stderr);
	return TPM_RC_ASYMMETRIC;
}

EVP_PKEY *
openssl_read_key(char *filename)
{
        BIO *b = NULL;
	EVP_PKEY *pkey;
	PKCS12 *p12;

        b = BIO_new_file(filename, "r");
        if (b == NULL) {
                fprintf(stderr, "Error opening file for read: %s\n", filename);
                return NULL;
        }

	p12 = d2i_PKCS12_bio(b, NULL);
	if (p12) {
		const char *pass;
		char buf[PEM_BUFSIZE];
		if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0)) {
			pass = "";
		} else {
			int len;

			len = PEM_def_callback(buf, sizeof(buf), 0, NULL);
			if (len < 0) {
				fprintf(stderr, "Getting password for pkcs12 failed.\n");
				openssl_print_errors();
				goto out;
			}
			buf[len] = '\0';
			pass = buf;
		}
		PKCS12_parse(p12, pass, &pkey, NULL, NULL);
		if (!pkey) {
			fprintf(stderr, "pkcs12 parsing failure.\n");
			openssl_print_errors();
		}
		goto out;
	}

	/* must be plain PEM private key, so reset everything */
	ERR_clear_error();
	BIO_reset(b);

        if ((pkey = PEM_read_bio_PrivateKey(b, NULL, PEM_def_callback, NULL)) == NULL) {
                fprintf(stderr, "Reading key %s from disk failed.\n", filename);
                openssl_print_errors();
        }
 out:
	BIO_free(b);

        return pkey;
}

EVP_PKEY *
openssl_read_public_key(char *filename)
{
        BIO *b = NULL;
	EVP_PKEY *pkey;

        b = BIO_new_file(filename, "r");
        if (b == NULL) {
                fprintf(stderr, "Error opening file for read: %s\n", filename);
                return NULL;
        }

        if ((pkey = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL)) == NULL) {
                fprintf(stderr, "Reading key %s from disk failed.\n", filename);
                openssl_print_errors();
        }
	BIO_free(b);

        return pkey;
}

void tpm2_public_template_rsa(TPMT_PUBLIC *pub)
{
	pub->type = TPM_ALG_RSA;
	pub->nameAlg = name_alg;
	/* note: all our keys are decrypt only.  This is because
	 * we use the TPM2_RSA_Decrypt operation for both signing
	 * and decryption (see e_tpm2.c for details) */
	pub->objectAttributes.val =
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_USERWITHAUTH;
	pub->authPolicy.t.size = 0;
	pub->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	pub->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
}

void tpm2_public_template_ecc(TPMT_PUBLIC *pub, TPMI_ECC_CURVE curve)
{
	pub->type = TPM_ALG_ECC;
	pub->nameAlg = name_alg;
	/* note: all our keys are decrypt only.  This is because
	 * we use the TPM2_RSA_Decrypt operation for both signing
	 * and decryption (see e_tpm2.c for details) */
	pub->objectAttributes.val =
		TPMA_OBJECT_SIGN |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_USERWITHAUTH;
	pub->authPolicy.t.size = 0;
	pub->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	pub->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	pub->parameters.eccDetail.curveID = curve;
	pub->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	pub->unique.ecc.x.t.size = 0;
	pub->unique.ecc.y.t.size = 0;
}

TPM_RC openssl_to_tpm_public_ecc(TPMT_PUBLIC *pub, EVP_PKEY *pkey)
{
	EC_KEY *eck = EVP_PKEY_get1_EC_KEY(pkey);
	const EC_GROUP *g = EC_KEY_get0_group(eck);
	const EC_POINT *P;
	TPMI_ECC_CURVE curve = tpm2_get_curve_name(g);
	TPM_RC rc = TPM_RC_CURVE;
	BN_CTX *ctx = NULL;
	BIGNUM *x, *y;

	if (curve == TPM_ECC_NONE) {
		fprintf(stderr, "TPM does not support the curve in this EC key\n");
		goto err;
	}
	tpm2_public_template_ecc(pub, curve);
	P = EC_KEY_get0_public_key(eck);

	if (!P) {
		fprintf(stderr, "No public key available\n");
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Unable to allocate context\n");
		goto err;
	}

	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	if (!x || !y) {
		fprintf(stderr, "Unable to allocate co-ordinates\n");
		goto err;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(g, P, x, y, ctx)) {
		fprintf(stderr, "Unable to get public key co-ordinates\n");
		goto err;
	}

	pub->unique.ecc.x.t.size = BN_bn2bin(x, pub->unique.ecc.x.t.buffer);
	pub->unique.ecc.y.t.size = BN_bn2bin(y, pub->unique.ecc.y.t.buffer);

	rc = TPM_RC_SUCCESS;

 err:
	if (ctx) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	EC_KEY_free(eck);

	return rc;
}

TPM_RC openssl_to_tpm_public_rsa(TPMT_PUBLIC *pub, EVP_PKEY *pkey)
{
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);
	const BIGNUM *n, *e;
	int size = RSA_size(rsa);
	unsigned long exp;
	TPM_RC rc = TPM_RC_KEY_SIZE;

	if (size > MAX_RSA_KEY_BYTES)
		goto err;

#if OPENSSL_VERSION_NUMBER < 0x10100000
	n = rsa->n;
	e = rsa->e;
#else
	RSA_get0_key(rsa, &n, &e, NULL);
#endif
	exp = BN_get_word(e);
	/* TPM limitations means exponents must be under a word in size */
	if (exp == 0xffffffffL)
		goto err;
	tpm2_public_template_rsa(pub);
	pub->parameters.rsaDetail.keyBits = size*8;
	/* zero means standard exponent.  Some TPM chips will
	 * reject a non standard exponent */
	if (exp == 0x10001)
		pub->parameters.rsaDetail.exponent = 0;
	else
		pub->parameters.rsaDetail.exponent = exp;

	pub->unique.rsa.t.size = BN_bn2bin(n, pub->unique.rsa.t.buffer);

	rc = 0;
 err:
	RSA_free(rsa);

	return rc;
}

TPM_RC openssl_to_tpm_public(TPM2B_PUBLIC *pub, EVP_PKEY *pkey)
{
	TPMT_PUBLIC *tpub = &pub->publicArea;
	pub->size = sizeof(*pub);

	switch (EVP_PKEY_type(EVP_PKEY_id(pkey))) {
	case EVP_PKEY_RSA:
		return openssl_to_tpm_public_rsa(tpub, pkey);
	case EVP_PKEY_EC:
		return openssl_to_tpm_public_ecc(tpub, pkey);
	default:
		break;
	}
	return TPM_RC_ASYMMETRIC;
}

TPM_RC openssl_to_tpm_private_ecc(TPMT_SENSITIVE *s, EVP_PKEY *pkey)
{
	const BIGNUM *pk;
	TPM2B_ECC_PARAMETER *t2becc = &s->sensitive.ecc;
	EC_KEY *eck = EVP_PKEY_get1_EC_KEY(pkey);
	TPM_RC rc = TPM_RC_KEY;

	if (!eck) {
		printf("Could not get EC Key\n");
		return rc;
	}

	pk = EC_KEY_get0_private_key(eck);

	if (!pk) {
		printf("Could not get Private Key\n");
		goto out;
	}

	t2becc->t.size = BN_bn2bin(pk, t2becc->t.buffer);
	s->sensitiveType = TPM_ALG_ECC;
	s->seedValue.b.size = 0;

	rc = TPM_RC_SUCCESS;

 out:
	EC_KEY_free(eck);

	return rc;
}

TPM_RC openssl_to_tpm_private_rsa(TPMT_SENSITIVE *s, EVP_PKEY *pkey)
{
	const BIGNUM *q;
	TPM2B_PRIVATE_KEY_RSA *t2brsa = &s->sensitive.rsa;
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	q = rsa->q;
#else
	const BIGNUM *p;

	RSA_get0_factors(rsa, &p, &q);
#endif

	if (!q)
		return TPM_RC_ASYMMETRIC;

	s->sensitiveType = TPM_ALG_RSA;
	s->seedValue.b.size = 0;

	t2brsa->t.size = BN_bn2bin(q, t2brsa->t.buffer);
	return 0;
}

TPM_RC openssl_to_tpm_private(TPMT_SENSITIVE *priv, EVP_PKEY *pkey)
{
	switch (EVP_PKEY_type(EVP_PKEY_id(pkey))) {
	case EVP_PKEY_RSA:
		return openssl_to_tpm_private_rsa(priv, pkey);
	case EVP_PKEY_EC:
		return openssl_to_tpm_private_ecc(priv, pkey);
	default:
		break;
	}
	return TPM_RC_ASYMMETRIC;
}

TPM_RC wrap_key(TPMT_SENSITIVE *s, const char *password, EVP_PKEY *pkey)
{
	TPM_RC rc;

	memset(s, 0, sizeof(*s));

	rc = openssl_to_tpm_private(s, pkey);
	if (rc != TPM_RC_SUCCESS)
		return rc;

	if (password) {
		int len = strlen(password);

		memcpy(s->authValue.b.buffer, password, len);
		s->authValue.b.size = len;
	} else {
		s->authValue.b.size = 0;
	}
	return TPM_RC_SUCCESS;
}

static void list_curves(void)
{
	TSS_CONTEXT *tssContext;
	GetCapability_In in;
	GetCapability_Out out;
	TPML_ECC_CURVE *c;
	const char *reason;
	TPM_RC rc;
	int i;

	rc = TSS_Create(&tssContext);
	if (rc) {
		reason = "TSS_Create";
		goto out_err;
	}

	in.capability = TPM_CAP_ECC_CURVES;
	in.property = 0;
	in.propertyCount = MAX_ECC_CURVES;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		reason = "TPM2_GetCapability";
		goto out_err;
	}
	TSS_Delete(tssContext);

	c = (TPML_ECC_CURVE *)&(out.capabilityData.data);

	for (i = 0; i < c->count; i++) {
		const char *name = tpm2_curve_name_to_text(c->eccCurves[i]);

		if (name)
			printf("%s\n", name);
		else
			printf("Curve %d Unsupported\n", c->eccCurves[i]);
	}

	return;
 out_err:
	tpm2_error(rc, reason);

	exit(1);
}

/*
 * A restricted key needs a symmetric seed and algorithm so it can
 * derive a symmetric encryption key used to protect the sensitive
 * parts of child objects.  The requirement is that the symmetric seed
 * be the same size as the name algorithm hash.  We elect to generate
 * the symmetric seed from the hash of the public and private parts of
 * the key meaning the same wrapped private key always generates the
 * same symmetric seed.  This means that any child key will be
 * loadable by any parent created from the wrapped key (including a
 * parent wrapped for a different TPM)
 */
void generate_symmetric(TPMT_PUBLIC *pub, TPMT_SENSITIVE *priv)
{
	TPMT_HA digest;

	digest.hashAlg = pub->nameAlg;

	switch (pub->type) {
	case TPM_ALG_RSA:
		TSS_Hash_Generate(&digest,
				  pub->unique.rsa.t.size, pub->unique.rsa.t.buffer,
				  priv->sensitive.rsa.t.size, priv->sensitive.rsa.t.buffer,
				  0, NULL);
		pub->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
		pub->parameters.rsaDetail.symmetric.keyBits.aes = 128;
		pub->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
		break;
	case TPM_ALG_ECC:
		TSS_Hash_Generate(&digest,
				  pub->unique.ecc.x.t.size, pub->unique.ecc.x.t.buffer,
				  pub->unique.ecc.y.t.size, pub->unique.ecc.y.t.buffer,
				  priv->sensitive.ecc.t.size, priv->sensitive.ecc.t.buffer,
				  0, NULL);
		pub->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
		pub->parameters.eccDetail.symmetric.keyBits.aes = 128;
		pub->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
		break;
	default:
		/* impossible */
		break;
	}
	priv->seedValue.b.size = TSS_GetDigestSize(digest.hashAlg);
	memcpy(priv->seedValue.b.buffer, digest.digest.tssmax, priv->seedValue.b.size);
	pub->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	/* a restricted key can't sign */
	pub->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
}

int main(int argc, char **argv)
{
	char *filename, *wrap = NULL, *auth = NULL, *policyFilename = NULL;
	int option_index, c;
	const char *reason;
	TSS_CONTEXT *tssContext = NULL;
	TPM_HANDLE parent = TPM_RH_OWNER, phandle;
	TPM_RC rc;
	BYTE pubkey[sizeof(TPM2B_PUBLIC)],privkey[sizeof(TPM2B_PRIVATE)], *buffer;
	uint16_t pubkey_len, privkey_len;
	int32_t size, key_size = 0;
	Import_In iin;
	Import_Out iout;
	Create_In cin;
	Create_Out cout;
	TPM2B_PUBLIC *pub;
	TPM2B_PRIVATE *priv;
	char *key = NULL, *parent_auth = NULL, *import = NULL;
	TPMI_ECC_CURVE ecc = TPM_ECC_NONE;
	int rsa = -1;
	uint32_t noda = TPMA_OBJECT_NODA;
	TPM_HANDLE authHandle;
	const char *dir;
	STACK_OF(TSSOPTPOLICY) *sk = NULL;
	int version = 1;
	uint32_t sizeInBytes;
	TPMT_HA digest;
	TPM2B_ENCRYPTED_SECRET secret, *enc_secret = NULL;
	int restricted = 0;

	OpenSSL_add_all_digests();
	/* may be needed to decrypt the key */
	OpenSSL_add_all_ciphers();

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "n:s:ab:p:hw:vk:re:ldc:i:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				auth = malloc(128);
				break;
			case 'b':
				parent_auth = optarg;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 'n':
				if (!strcasecmp("sha1", optarg)) {
					name_alg = TPM_ALG_SHA1;
				} else if (!strcasecmp("sha256", optarg)) {
					/* default, do nothing */
				} else if (!strcasecmp("sha384", optarg)) {
					name_alg = TPM_ALG_SHA384;
#ifdef TPM_ALG_SHA512
				} else if (!strcasecmp("sha512", optarg)) {
					name_alg = TPM_ALG_SHA512;
#endif
				} else {
					usage(argv[0]);
				}
				break;
			case 'p':
				parent = tpm2_get_parent(optarg);
				if (parent == 0) {
					fprintf(stderr, "Invalid parent %s\n", optarg);
					exit(1);
				}
				break;
			case 's':
				key_size = atoi(optarg);
				break;
			case 'w':
				wrap = optarg;
				break;
			case 'v':
				fprintf(stdout, "%s " VERSION "\n"
					"Copyright 2017 by James Bottomley\n"
					"License LGPL-2.1-only\n"
					"Written by James Bottomley <James.Bottomley@HansenPartnership.com>\n",
					argv[0]);
				exit(0);
			case 'k':
				key = optarg;
				if (strlen(key) > 127) {
					printf("password is too long\n");
					exit(1);
				}
				break;
			case 'r':
				rsa = 1;
				break;
			case 'e':
				ecc = tpm2_curve_name_to_TPMI(optarg);
				if (ecc == TPM_ECC_NONE) {
					printf("Unknown Curve\n");
					exit(1);
				}
				break;
			case 'l':
				list_curves();
				exit(0);
			case 'd':
				noda = 0;
				break;
			case 'c':
				policyFilename = optarg;
				break;
			case 'i':
				import = optarg;
				break;
			case OPT_DEPRECATED:
				version = 0;
				break;
			case OPT_RESTRICTED:
				restricted = 1;
				break;
			default:
				printf("Unknown option '%c'\n", c);
				usage(argv[0]);
				break;
		}
	}

	if (optind >= argc) {
		printf("Too few arguments: Expected file name as last argument\n");
		usage(argv[0]);
	}

	filename = argv[argc - 1];

	if (optind < argc - 1) {
		printf("Unexpected additional arguments\n");
		usage(argv[0]);
	}

	if (key_size && wrap) {
		fprintf(stderr, "key-size and wrap are mutually exclusive\n");
		usage(argv[0]);
	} else if (!key_size && !wrap) {
		/* for internal create, use default key size */
		key_size = 2048;
	}

	if (rsa == 1 && ecc != TPM_ECC_NONE) {
		fprintf(stderr, "Cannot specify both --rsa and --ecc\n");
		exit(1);
	} else if (ecc != TPM_ECC_NONE) {
		rsa = 0;
	}

	if (import && !wrap) {
		fprintf(stderr, "Can only wrap importable keys\n");
		exit(1);
	}

	digest.hashAlg = name_alg;
	sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	memset((uint8_t *)&digest.digest, 0, sizeInBytes);

	if (policyFilename) {
		sk = sk_TSSOPTPOLICY_new_null();
		if (!sk) {
			rc = NOT_TPM_ERROR;
			reason="sk_TSSOPTPOLICY_new_null allocation";
			goto out_err;
		}

		rc = tpm2_parse_policy_file(policyFilename, sk, auth, &digest);
		if (rc) {
			reason = "parse_policy_file";
			goto out_free_policy;
		}
	}

	if (auth) {
		if (key) {
			/* key length already checked */
			strcpy(auth, key);
		} else {
			if (EVP_read_pw_string(auth, 128, "Enter TPM key authority: ", 1)) {
				fprintf(stderr, "Passwords do not match\n");
				reason = "authorization";
				rc = NOT_TPM_ERROR;
				goto out_free_auth;
			}
		}
	}

	if (import) {
		EVP_PKEY *p_pkey = openssl_read_public_key(import);
		EVP_PKEY *pkey = openssl_read_key(wrap);
		TPMT_SENSITIVE s;

		/* steal existing private and public areas */
		pub = &iin.objectPublic;
		priv = &iout.outPrivate;

		rc = NOT_TPM_ERROR;

		if (!p_pkey || !pkey) {
			reason = "read openssl key";
			goto out_err;
		}

		/* FIXME: should do RSA as well, it's just more complex */
		if (EVP_PKEY_type(EVP_PKEY_id(p_pkey)) != EVP_PKEY_EC) {
			reason = "parent not EC key";
			goto out_err;
		}

		rc = openssl_to_tpm_public(pub, pkey);
		if (rc) {
			reason = "openssl_to_tpm_public";
			goto out_err;
		}
		if (policyFilename) {
			pub->publicArea.objectAttributes.val &=
				~TPMA_OBJECT_USERWITHAUTH;
			rc = TSS_TPM2B_Create(
				&pub->publicArea.authPolicy.b,
				(uint8_t *)&digest.digest, sizeInBytes,
				sizeof(TPMU_HA));
			if (rc) {
				reason = "set policy";
				goto out_err;
			}
		}

		rc = wrap_key(&s, auth, pkey);
		if (rc) {
			reason = "wrap_key";
			goto out_err;
		}

		/* set the NODA flag */
		pub->publicArea.objectAttributes.val |= noda;

		if (restricted)
			generate_symmetric(&pub->publicArea, &s);

		rc = tpm2_outerwrap(p_pkey, &s, &pub->publicArea,
				    priv, &secret);
		if (rc) {
			reason = "tpm2_outerwrap";
			goto out_err;
		}

		enc_secret = &secret;

		/* skip over all the TPM connection stuff  */
		goto write_key;
	}

	dir = tpm2_set_unique_tssdir();
	rc = tpm2_create(&tssContext, dir);
	if (rc) {
		reason = "TSS_Create";
		goto out_free_auth;
	}

	if ((parent & 0xff000000) == 0x40000000) {
		rc = tpm2_load_srk(tssContext, &phandle, parent_auth, NULL, parent, version);
		if (rc) {
			reason = "tpm2_load_srk";
			goto out_delete;
		}
	} else {
		phandle = parent;
	}

	if (wrap) {
		EVP_PKEY *pkey;
		TPMT_SENSITIVE s;

		pkey = openssl_read_key(wrap);
		if (!pkey) {
			rc = NOT_TPM_ERROR;
			reason = "read openssl key";
			goto out_flush;
		}

		iin.parentHandle = phandle;

		rc = RAND_bytes(iin.encryptionKey.t.buffer, T2_AES_KEY_BYTES);
		if (!rc) {
			reason = "Can't get a random AES key for parameter encryption";
			goto out_flush;
		}
		iin.encryptionKey.t.size = T2_AES_KEY_BYTES;
		/* set random iin.symSeed */
		iin.inSymSeed.t.size = 0;
		iin.symmetricAlg.algorithm = TPM_ALG_AES;
		iin.symmetricAlg.keyBits.aes = T2_AES_KEY_BITS;
		iin.symmetricAlg.mode.aes = TPM_ALG_CFB;

		rc = wrap_key(&s, auth, pkey);
		if (rc) {
			reason = "wrap_key";
			goto out_flush;
		}
		rc = openssl_to_tpm_public(&iin.objectPublic, pkey);
		if (rc) {
			reason = "openssl_to_tpm_public";
			goto out_flush;
		}

		if (policyFilename) {
			iin.objectPublic.publicArea.objectAttributes.val &=
				~TPMA_OBJECT_USERWITHAUTH;
			rc = TSS_TPM2B_Create(
				&iin.objectPublic.publicArea.authPolicy.b,
				(uint8_t *)&digest.digest, sizeInBytes,
				sizeof(TPMU_HA));
			if (rc) {
				reason = "set policy";
				goto out_flush;
			}
		}

		/* set the NODA flag */
		iin.objectPublic.publicArea.objectAttributes.val |= noda;

		if (restricted)
			generate_symmetric(&iin.objectPublic.publicArea, &s);

		rc = tpm2_innerwrap(&s, &iin.objectPublic.publicArea,
				    &iin.symmetricAlg,
				    &iin.encryptionKey,
				    &iin.duplicate);
		if (rc) {
			reason = "tpm2_innerwrap";
			goto out_flush;
		}

		/* use salted parameter encryption to hide the key */
		rc = tpm2_get_session_handle(tssContext, &authHandle, phandle,
					     TPM_SE_HMAC, name_alg);
		if (rc) {
			reason = "get session handle";
			goto out_flush;
		}

		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&iout,
				 (COMMAND_PARAMETERS *)&iin,
				 NULL,
				 TPM_CC_Import,
				 authHandle, parent_auth, TPMA_SESSION_DECRYPT,
				 TPM_RH_NULL, NULL, 0);
		if (rc) {
			reason = "TPM2_Import";
			/* failure means auth handle is not flushed */
			tpm2_flush_handle(tssContext, authHandle);
			goto out_flush;
		}
		pub = &iin.objectPublic;
		priv = &iout.outPrivate;
 	} else {
		/* create a TPM resident key */
		if (rsa) {
			tpm2_public_template_rsa(&cin.inPublic.publicArea);
			cin.inPublic.publicArea.parameters.rsaDetail.keyBits = key_size;
			cin.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
			cin.inPublic.publicArea.unique.rsa.t.size = 0;

		} else {
			tpm2_public_template_ecc(&cin.inPublic.publicArea, ecc);
		}

		if (policyFilename) {
			cin.inPublic.publicArea.objectAttributes.val &=
				~TPMA_OBJECT_USERWITHAUTH;
			rc = TSS_TPM2B_Create(
				&cin.inPublic.publicArea.authPolicy.b,
				(uint8_t *)&digest.digest, sizeInBytes,
				sizeof(TPMU_HA));
			if (rc) {
				reason = "set policy";
				goto out_flush;
			}
		}

		cin.inPublic.publicArea.objectAttributes.val |=
			noda |
			TPMA_OBJECT_SENSITIVEDATAORIGIN;
		if (restricted) {
			cin.inPublic.publicArea.objectAttributes.val |=
				TPMA_OBJECT_RESTRICTED;
			cin.inPublic.publicArea.objectAttributes.val &=
				~TPMA_OBJECT_SIGN;
			cin.inPublic.publicArea.parameters.asymDetail.symmetric.algorithm = TPM_ALG_AES;
			cin.inPublic.publicArea.parameters.asymDetail.symmetric.keyBits.aes = 128;
			cin.inPublic.publicArea.parameters.asymDetail.symmetric.mode.aes = TPM_ALG_CFB;
		}
		if (auth) {
			int len = strlen(auth);
			memcpy(&cin.inSensitive.sensitive.userAuth.b.buffer,
			       auth, len);
			cin.inSensitive.sensitive.userAuth.b.size = len;
		} else {
			cin.inSensitive.sensitive.userAuth.b.size = 0;
		}
		cin.inSensitive.sensitive.data.t.size = 0;
		cin.parentHandle = phandle;
		cin.outsideInfo.t.size = 0;
		cin.creationPCR.count = 0;

		/* use salted parameter encryption to hide the key */
		rc = tpm2_get_session_handle(tssContext, &authHandle, phandle,
					     TPM_SE_HMAC, name_alg);
		if (rc) {
			reason = "get session handle";
			goto out_flush;
		}

		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&cout,
				 (COMMAND_PARAMETERS *)&cin,
				 NULL,
				 TPM_CC_Create,
				 authHandle, parent_auth, TPMA_SESSION_DECRYPT,
				 TPM_RH_NULL, NULL, 0);
		if (rc) {
			reason = "TPM2_Create";
			/* failure means auth handle is not flushed */
			tpm2_flush_handle(tssContext, authHandle);
			goto out_flush;
		}

		pub = &cout.outPublic;
		priv = &cout.outPrivate;
	}
	tpm2_flush_srk(tssContext, phandle);
	TSS_Delete(tssContext);
	tpm2_rm_keyfile(dir, phandle);
	tpm2_rm_tssdir(dir);

 write_key:
	buffer = pubkey;
	pubkey_len = 0;
	size = sizeof(pubkey);
	TSS_TPM2B_PUBLIC_Marshal(pub, &pubkey_len, &buffer, &size);
	buffer = privkey;
	privkey_len = 0;
	size = sizeof(privkey);
	TSS_TPM2B_PRIVATE_Marshal(priv, &privkey_len, &buffer, &size);
	tpm2_write_tpmfile(filename, pubkey, pubkey_len,
			   privkey, privkey_len, auth == NULL, parent, sk,
			   version, enc_secret);
	tpm2_free_policy(sk);

	exit(0);

 out_flush:
	tpm2_flush_srk(tssContext, phandle);
 out_delete:
	TSS_Delete(tssContext);
	rmdir(dir);
 out_free_auth:
	free(auth);
 out_free_policy:
	tpm2_free_policy(sk);
 out_err:
	if (rc == NOT_TPM_ERROR)
		fprintf(stderr, "%s failed\n", reason);
	else
		tpm2_error(rc, reason);

	exit(1);
}
