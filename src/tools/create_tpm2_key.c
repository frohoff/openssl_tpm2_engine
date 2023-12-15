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

#include "tpm2-tss.h"
#include "tpm2-asn.h"
#include "tpm2-common.h"

#define OPT_DEPRECATED 0x1ff
#define OPT_RESTRICTED 0x1fe
#define OPT_SIGNED_POLICY 0x1fd
#define OPT_LOCALITY 0x1fc
#define OPT_SECRET 0x1fb

static struct option long_options[] = {
	{"auth", 0, 0, 'a'},
	{"auth-parent", 1, 0, 'b'},
	{"help", 0, 0, 'h'},
	{"key-size", 1, 0, 's'},
	{"name-scheme", 1, 0, 'n'},
	{"parent-handle", 1, 0, 'p'},
	{"pcr-lock", 1, 0, 'x'},
	{"signed-policy", 1, 0, OPT_SIGNED_POLICY },
	{"locality", 1, 0, OPT_LOCALITY },
	{"wrap", 1, 0, 'w'},
	{"version", 0, 0, 'v'},
	{"password", 1, 0, 'k'},
	{"rsa", 0, 0, 'r'},
	{"ecc", 1, 0, 'e'},
	{"list-curves", 0, 0, 'l'},
	{"da", 0, 0, 'd'},
	{"key-policy", 1, 0, 'c'},
	{"import", 1, 0, 'i'},
	{"restricted", 0, 0, OPT_RESTRICTED },
	{"secret", 1, 0, OPT_SECRET },
	/*
	 * The option --deprecated allows us to create old format keys
	 * for the purposes of testing.  It should never be used in
	 * the field so is an undocumented option
	 */
	{"deprecated", 0, 0, OPT_DEPRECATED},
	{0, 0, 0, 0}
};

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
		"\t-x, --pcr-lock <pcrs>         Lock the created key to the specified PCRs\n"
		"                                By current value.  See PCR VALUES for\n"
		"                                details about formatting\n"
		"\t--locality <loc>              Can only be used in a set of localities\n"
		"                                described by the <loc> bitmap\n"
		"\t--signed-policy <key>         Add a signed policy directive that allows\n"
		"\t                              policies signed by the specified public <key>\n"
		"\t                              to authorize use of the key\n"
		"\t--secret <handle>             Tie authorization of the key to the\n"
		"\t                              Authorization of a different object\n"
		"\t                              Identified by <handle>.\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
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
		      DATA_2B *innerkey,
		      PRIVATE_2B *p)
{
	BYTE *buf = p->buffer;

	p->size = 0;
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
		NAME_2B name;

		/* WARNING: don't use the static null_iv trick here:
		 * the AES routines alter the passed in iv */
		memset(null_iv, 0, sizeof(null_iv));

		/* reserve space for hash before the encrypted sensitive */
		bsize = sizeof(digest->size) + hlen;
		buf += bsize;
		p->size += bsize;
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
		p->size += bsize;

		tpm2_ObjectPublic_GetName(&name, pub);
		/* compute hash of unencrypted marshalled sensitive and
		 * write to the digest buffer */
		hash.hashAlg = nalg;
		TSS_Hash_Generate(&hash, bsize, s2b,
				  name.size, name.name,
				  0, NULL);
		memcpy(digest->buffer, &hash.digest, hlen);

		/* encrypt hash and sensitive in place */
		TSS_AES_EncryptCFB(p->buffer,
				   symdef->keyBits.aes,
				   innerkey->buffer,
				   null_iv,
				   p->size,
				   p->buffer);
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

		p->size += bsize + sizeof(s2b->size);
	} else {
		printf("Unknown symmetric algorithm\n");
		return TPM_RC_SYMMETRIC;
	}

	return TPM_RC_SUCCESS;
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

TPM_RC openssl_to_tpm_private_ecc(TPMT_SENSITIVE *s, EVP_PKEY *pkey)
{
	const BIGNUM *pk;
	ECC_PARAMETER_2B *t2becc = (ECC_PARAMETER_2B *)&s->sensitive.ecc;
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

	t2becc->size = BN_bn2bin(pk, t2becc->buffer);
	s->sensitiveType = TPM_ALG_ECC;
	VAL_2B(s->seedValue, size) = 0;

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
	VAL_2B(s->seedValue, size) = 0;

	VAL_2B_P(t2brsa, size) = BN_bn2bin(q, VAL_2B_P(t2brsa, buffer));
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

		memcpy(VAL_2B(s->authValue, buffer), password, len);
		VAL_2B(s->authValue, size) = len;
	} else {
		VAL_2B(s->authValue, size) = 0;
	}
	return TPM_RC_SUCCESS;
}

static void list_curves(void)
{
	TSS_CONTEXT *tssContext;
	TPMS_CAPABILITY_DATA capabilityData;
	TPML_ECC_CURVE *c;
	const char *reason;
	TPM_RC rc;
	int i;

	rc = tpm2_create(&tssContext, NULL);
	if (rc) {
		reason = "TSS_Create";
		goto out_err;
	}

	rc = tpm2_GetCapability(tssContext, TPM_CAP_ECC_CURVES, 0,
				MAX_ECC_CURVES, NULL, &capabilityData);

	if (rc) {
		reason = "TPM2_GetCapability";
		goto out_err;
	}
	TSS_Delete(tssContext);

	c = (TPML_ECC_CURVE *)&(capabilityData.data);

	for (i = 0; i < c->count; i++) {
		const char *name = tpm2_curve_name_to_text(c->eccCurves[i]);

		if (name)
			printf("%s\n", name);
		else
			fprintf(stderr, "Curve %d Unsupported\n", c->eccCurves[i]);
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
				  VAL_2B(pub->unique.rsa, size),
				  VAL_2B(pub->unique.rsa, buffer),
				  VAL_2B(priv->sensitive.rsa, size),
				  VAL_2B(priv->sensitive.rsa, buffer),
				  0, NULL);
		pub->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
		pub->parameters.rsaDetail.symmetric.keyBits.aes = 128;
		pub->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
		break;
	case TPM_ALG_ECC:
		TSS_Hash_Generate(&digest,
				  VAL_2B(pub->unique.ecc.x, size),
				  VAL_2B(pub->unique.ecc.x, buffer),
				  VAL_2B(pub->unique.ecc.y, size),
				  VAL_2B(pub->unique.ecc.y, buffer),
				  VAL_2B(priv->sensitive.ecc, size),
				  VAL_2B(priv->sensitive.ecc, buffer),
				  0, NULL);
		pub->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
		pub->parameters.eccDetail.symmetric.keyBits.aes = 128;
		pub->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
		break;
	default:
		/* impossible */
		break;
	}
	VAL_2B(priv->seedValue, size) = TSS_GetDigestSize(digest.hashAlg);
	memcpy(VAL_2B(priv->seedValue, buffer),
	       &digest.digest, VAL_2B(priv->seedValue, size));
	VAL(pub->objectAttributes) |= TPMA_OBJECT_RESTRICTED;
	/* a restricted key can't sign */
	VAL(pub->objectAttributes) &= ~TPMA_OBJECT_SIGN;
}

int main(int argc, char **argv)
{
	char *filename, *wrap = NULL, *auth = NULL, *policyFilename = NULL;
	int option_index, c;
	const char *reason;
	TSS_CONTEXT *tssContext = NULL;
	TPM_HANDLE parent = TPM_RH_OWNER, phandle, secret_handle = 0;
	TPM_RC rc;
	BYTE pubkey[sizeof(TPM2B_PUBLIC)],privkey[sizeof(TPM2B_PRIVATE)], *buffer;
	uint16_t pubkey_len, privkey_len;
	int32_t size, key_size = 0;
	TPM2B_PUBLIC objectPublic;
	DATA_2B encryptionKey;
	PRIVATE_2B duplicate;
	ENCRYPTED_SECRET_2B inSymSeed;
	TPMT_SYM_DEF_OBJECT symmetricAlg;
	TPM2B_SENSITIVE_CREATE inSensitive;
	TPM2B_PUBLIC outPublic;
	PRIVATE_2B outPrivate;
	TPM2B_PUBLIC *pub;
	PRIVATE_2B *priv;
	char *key = NULL, *parent_auth = NULL, *import = NULL;
	char *signed_policy = NULL;
	TPMI_ECC_CURVE ecc = TPM_ECC_NONE;
	int rsa = -1;
	uint32_t noda = TPMA_OBJECT_NODA;
	TPM_HANDLE authHandle;
	const char *dir;
	STACK_OF(TSSOPTPOLICY) *sk = NULL;
	int version = 1;
	uint32_t sizeInBytes;
	TPMT_HA digest;
	ENCRYPTED_SECRET_2B secret, *enc_secret = NULL;
	int restricted = 0;
	char *parent_str = NULL;
	TPML_PCR_SELECTION pcr_lock = { 0 };
	int has_policy = 0, has_locality = 0;
	UINT8 locality = 0;

	OpenSSL_add_all_digests();
	/* may be needed to decrypt the key */
	OpenSSL_add_all_ciphers();

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "n:s:ab:p:hw:vk:re:ldc:i:x:",
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
				parent_str = optarg;
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
			case 'x':
				tpm2_get_pcr_lock(&pcr_lock, optarg);
				break;
			case OPT_DEPRECATED:
				version = 0;
				break;
			case OPT_RESTRICTED:
				restricted = 1;
				break;
			case OPT_SIGNED_POLICY:
				signed_policy = optarg;
				break;
			case OPT_LOCALITY:
				has_locality = 1;
				locality = strtol(optarg, NULL, 0);
				break;
			case OPT_SECRET:
				secret_handle = strtol(optarg, NULL, 0);
				has_policy = 1;
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

	if (signed_policy && policyFilename) {
		fprintf(stderr, "cannot specify both signed policy and policy file\n");
		exit(1);
	}

	if (pcr_lock.count !=0 && policyFilename) {
		fprintf(stderr, "cannot specify both policy file and pcr lock\n");
		exit(1);
	}

	if (pcr_lock.count != 0 && import) {
		fprintf(stderr, "cannot specify pcr lock and import because pcrs may not be correct\n");
		exit(1);
	}

	if (has_locality && locality == 0) {
		fprintf(stderr, "zero is an illegal locality bitmap\n");
		exit(1);
	}

	if (pcr_lock.count != 0 || policyFilename || signed_policy ||
	    has_locality)
		has_policy = 1;

	digest.hashAlg = name_alg;
	sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	memset((uint8_t *)&digest.digest, 0, sizeInBytes);

	if (has_policy) {
		sk = sk_TSSOPTPOLICY_new_null();
		if (!sk) {
			rc = NOT_TPM_ERROR;
			reason="sk_TSSOPTPOLICY_new_null allocation";
			goto out_err;
		}

		if (policyFilename) {
			rc = tpm2_parse_policy_file(policyFilename, sk, auth, &digest);
			reason = "parse_policy_file";
			if (rc)
				goto out_free_policy;
		} else if (signed_policy) {
			rc = tpm2_add_signed_policy(sk, signed_policy, &digest);
			reason = "add_signed_policy";
			if (rc)
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
		if (has_policy && !policyFilename)
			tpm2_add_auth_policy(sk, &digest);
	}

	if (has_locality)
		tpm2_add_locality(sk, locality, &digest);

	if (import) {
		EVP_PKEY *p_pkey = openssl_read_public_key(import);
		EVP_PKEY *pkey = openssl_read_key(wrap);
		TPMT_SENSITIVE s;

		rc = NOT_TPM_ERROR;

		if (parent_str) {
			parent = tpm2_get_parent_ext(parent_str);
			if (parent == 0) {
				reason = "Invalid parent";
				goto out_err;
			}
		} else {
			parent = EXT_TPM_RH_OWNER;
		}

		/* steal existing private and public areas */
		pub = &objectPublic;
		priv = &outPrivate;

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
		if (has_policy) {
			VAL(pub->publicArea.objectAttributes) &=
				~TPMA_OBJECT_USERWITHAUTH;
			rc = TSS_TPM2B_Create(
				(TPM2B *)&pub->publicArea.authPolicy,
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
		VAL(pub->publicArea.objectAttributes) |= noda;

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

	if (pcr_lock.count != 0) {
		rc = tpm2_pcr_lock_policy(tssContext, &pcr_lock,
					  sk, &digest);
		if (rc) {
			reason = "create pcr policy";
			goto out_free_auth;
		}
	}

	if (secret_handle)
		tpm2_add_policy_secret(tssContext, sk, secret_handle, &digest);

	if (parent_str) {
		parent = tpm2_get_parent(tssContext, parent_str);
		if (parent == 0) {
			reason = "Invalid parent";
			goto out_delete;
		}
	}

	if (tpm2_handle_mso(tssContext, parent, TPM_HT_PERMANENT)) {
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

		rc = RAND_bytes(encryptionKey.buffer, T2_AES_KEY_BYTES);
		if (!rc) {
			reason = "Can't get a random AES key for parameter encryption";
			goto out_flush;
		}
		encryptionKey.size = T2_AES_KEY_BYTES;
		/* set random iin.symSeed */
		inSymSeed.size = 0;
		symmetricAlg.algorithm = TPM_ALG_AES;
		symmetricAlg.keyBits.aes = T2_AES_KEY_BITS;
		symmetricAlg.mode.aes = TPM_ALG_CFB;

		rc = wrap_key(&s, auth, pkey);
		if (rc) {
			reason = "wrap_key";
			goto out_flush;
		}
		rc = openssl_to_tpm_public(&objectPublic, pkey);
		if (rc) {
			reason = "openssl_to_tpm_public";
			goto out_flush;
		}

		if (has_policy) {
			VAL(objectPublic.publicArea.objectAttributes) &=
				~TPMA_OBJECT_USERWITHAUTH;
			rc = TSS_TPM2B_Create(
				(TPM2B *)&objectPublic.publicArea.authPolicy,
				(uint8_t *)&digest.digest, sizeInBytes,
				sizeof(TPMU_HA));
			if (rc) {
				reason = "set policy";
				goto out_flush;
			}
		}

		/* set the NODA flag */
		VAL(objectPublic.publicArea.objectAttributes) |= noda;

		if (restricted)
			generate_symmetric(&objectPublic.publicArea, &s);

		rc = tpm2_innerwrap(&s, &objectPublic.publicArea,
				    &symmetricAlg,
				    &encryptionKey,
				    &duplicate);
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

		rc = tpm2_Import(tssContext, phandle, &encryptionKey,
				 &objectPublic, &duplicate, &inSymSeed,
				 &symmetricAlg, &outPrivate, authHandle,
				 parent_auth);
		if (rc) {
			reason = "TPM2_Import";
			/* failure means auth handle is not flushed */
			tpm2_flush_handle(tssContext, authHandle);
			goto out_flush;
		}
		pub = &objectPublic;
		priv = &outPrivate;
 	} else {
		/* create a TPM resident key */
		if (rsa) {
			tpm2_public_template_rsa(&objectPublic.publicArea);
			objectPublic.publicArea.parameters.rsaDetail.keyBits = key_size;
			objectPublic.publicArea.parameters.rsaDetail.exponent = 0;
			VAL_2B(objectPublic.publicArea.unique.rsa, size) = 0;

		} else {
			tpm2_public_template_ecc(&objectPublic.publicArea, ecc);
		}

		if (has_policy) {
			VAL(objectPublic.publicArea.objectAttributes) &=
				~TPMA_OBJECT_USERWITHAUTH;
			rc = TSS_TPM2B_Create(
				(TPM2B *)&objectPublic.publicArea.authPolicy,
				(uint8_t *)&digest.digest, sizeInBytes,
				sizeof(TPMU_HA));
			if (rc) {
				reason = "set policy";
				goto out_flush;
			}
		}

		VAL(objectPublic.publicArea.objectAttributes) |=
			noda |
			TPMA_OBJECT_SENSITIVEDATAORIGIN;
		if (restricted) {
			VAL(objectPublic.publicArea.objectAttributes) |=
				TPMA_OBJECT_RESTRICTED;
			VAL(objectPublic.publicArea.objectAttributes) &=
				~TPMA_OBJECT_SIGN;
			objectPublic.publicArea.parameters.asymDetail.symmetric.algorithm = TPM_ALG_AES;
			objectPublic.publicArea.parameters.asymDetail.symmetric.keyBits.aes = 128;
			objectPublic.publicArea.parameters.asymDetail.symmetric.mode.aes = TPM_ALG_CFB;
		}
		if (auth) {
			int len = strlen(auth);
			memcpy(&VAL_2B(inSensitive.sensitive.userAuth, buffer),
			       auth, len);
			VAL_2B(inSensitive.sensitive.userAuth, size) = len;
		} else {
			VAL_2B(inSensitive.sensitive.userAuth, size) = 0;
		}
		VAL_2B(inSensitive.sensitive.data, size) = 0;

		/* use salted parameter encryption to hide the key */
		rc = tpm2_get_session_handle(tssContext, &authHandle, phandle,
					     TPM_SE_HMAC, name_alg);
		if (rc) {
			reason = "get session handle";
			goto out_flush;
		}

		rc = tpm2_Create(tssContext, phandle, &inSensitive,
				 &objectPublic, &outPrivate, &outPublic,
				 authHandle, parent_auth);

		if (rc) {
			reason = "TPM2_Create";
			/* failure means auth handle is not flushed */
			tpm2_flush_handle(tssContext, authHandle);
			goto out_flush;
		}

		pub = &outPublic;
		priv = &outPrivate;
	}
	tpm2_flush_srk(tssContext, phandle);
	parent = tpm2_handle_ext(tssContext, parent);
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
	TSS_TPM2B_PRIVATE_Marshal((TPM2B_PRIVATE *)priv, &privkey_len, &buffer, &size);
	tpm2_write_tpmfile(filename, pubkey, pubkey_len,
			   privkey, privkey_len,
			   auth == NULL && secret_handle == 0, parent, sk,
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
