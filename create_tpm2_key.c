/*
 *
 *   Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 *   GPLv2
 */


#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssmarshal.h>

#include "tpm2-asn.h"
#include "tpm2-common.h"

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
	{0, 0, 0, 0}
};

static TPM_ALG_ID name_alg = TPM_ALG_SHA256;
static int name_alg_size = SHA256_DIGEST_SIZE;

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
		"\t-w, --wrap <file>             wrap an existing openssl PEM key\n"
		"\t-k, --password <pwd>          use this password instead of prompting\n"
		"\t-r, --rsa                     create an RSA key (the default)\n"
		"\t-e, --ecc <curve>             Create an ECC key using the specified curve.\n"
		"\t                              Supported curves are bnp256, nisp256, nisp384\n"
		"\t-l, --list-curves             List all the Elliptic Curves the TPM supports\n"
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

int
openssl_write_tpmfile(const char *file, BYTE *pubkey, int pubkey_len,
		      BYTE *privkey, int privkey_len, int empty_auth,
		      TPM_HANDLE parent)
{
	TSSLOADABLE tssl;
	BIO *outb;

	/* clear structure so as not to have to set optional parameters */
	memset(&tssl, 0, sizeof(tssl));
	if ((outb = BIO_new_file(file, "w")) == NULL) {
                fprintf(stderr, "Error opening file for write: %s\n", file);
		return 1;
	}
	tssl.type = OBJ_txt2obj(OID_loadableKey, 1);
	tssl.emptyAuth = empty_auth;
	tssl.parent = ASN1_INTEGER_new();
	ASN1_INTEGER_set(tssl.parent, parent);

	tssl.pubkey = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(tssl.pubkey, pubkey, pubkey_len);
	tssl.privkey = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(tssl.privkey, privkey, privkey_len);

	PEM_write_bio_TSSLOADABLE(outb, &tssl);
	BIO_free(outb);
	return 0;
}

EVP_PKEY *
openssl_read_key(char *filename)
{
        BIO *b = NULL;
	EVP_PKEY *pkey;

        b = BIO_new_file(filename, "r");
        if (b == NULL) {
                fprintf(stderr, "Error opening file for read: %s\n", filename);
                return NULL;
        }

        if ((pkey = PEM_read_bio_PrivateKey(b, NULL, PEM_def_callback, NULL)) == NULL) {
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

static TPM_HANDLE get_parent(const char *pstr)
{
	TPM_HANDLE p;

	if (strcmp(pstr, "owner") == 0)
		p = TPM_RH_OWNER;
	else if (strcmp(pstr, "platform") == 0)
		p = TPM_RH_PLATFORM;
	else if (strcmp(pstr, "endorsement") == 0)
		p = TPM_RH_ENDORSEMENT;
	else if (strcmp(pstr, "null") == 0)
		p = TPM_RH_NULL;
	else
		p = strtoul(pstr, NULL, 16);

	if (((p & 0xff000000) == 0x40000000) &&
	    (p == TPM_RH_OWNER ||
	     p == TPM_RH_PLATFORM ||
	     p == TPM_RH_ENDORSEMENT ||
	     p == TPM_RH_NULL))
		return p;
	else if ((p & 0xff000000) == 0x81000000)
		return p;

	return 0;
}

int main(int argc, char **argv)
{
	char *filename, *wrap = NULL, *auth = NULL;
	int option_index, c;
	const char *reason = "";
	TSS_CONTEXT *tssContext = NULL;
	TPM_HANDLE parent = TPM_RH_OWNER, phandle;
	TPM_RC rc = 0;
	BYTE pubkey[sizeof(TPM2B_PUBLIC)],privkey[sizeof(TPM2B_PRIVATE)], *buffer;
	uint16_t pubkey_len, privkey_len;
	int32_t size, key_size = 0;
	TPM2B_PUBLIC *pub;
	TPM2B_PRIVATE *priv;
	char *key = NULL, *parent_auth = NULL;
	TPMI_ECC_CURVE ecc = TPM_ECC_NONE;
	int rsa = -1;
	uint32_t noda = TPMA_OBJECT_NODA;
	TPM_HANDLE authHandle;
	const char *dir;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "n:s:ab:p:hw:vk:re:ld",
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
					name_alg_size = SHA1_DIGEST_SIZE;
				} else if (strcasecmp("sha256", optarg)) {
					/* default, do nothing */
				} else if (strcasecmp("sha384", optarg)) {
					name_alg = TPM_ALG_SHA384;
					name_alg_size = SHA384_DIGEST_SIZE;
#ifdef TPM_ALG_SHA512
				} else if (strcasecmp("sha512", optarg)) {
					name_alg = TPM_ALG_SHA512;
					name_alg_size = SHA512_DIGEST_SIZE;
#endif
				} else {
					usage(argv[0]);
				}
				break;
			case 'p':
				parent = get_parent(optarg);
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
					"License GPLv2: GNU GPL version 2\n"
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
			default:
				printf("Unknown option '%c'\n", c);
				usage(argv[0]);
				break;
		}
	}

	filename = argv[argc - 1];

	if (argc < 2) {
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
		printf("Cannot specify both --rsa and --ecc\n");
		exit(1);
	} else if (ecc != TPM_ECC_NONE) {
		rsa = 0;
	}

	if (auth) {
		if (key) {
			/* key length already checked */
			strcpy(auth, key);
		} else {
			if (EVP_read_pw_string(auth, 128, "Enter TPM key authority: ", 1)) {
				fprintf(stderr, "Passwords do not match\n");
				exit(1);
			}
		}
	}

	dir = tpm2_set_unique_tssdir();
	rc = tpm2_create(&tssContext, dir);
	if (rc) {
		reason = "TSS_Create";
		goto out_err;
	}

	if ((parent & 0xff000000) == 0x40000000) {
		rc = tpm2_load_srk(tssContext, &phandle, parent_auth, NULL, parent);
		if (rc) {
			reason = "tpm2_load_srk";
			goto out_delete;
		}
	} else {
		phandle = parent;
	}

	if (wrap) {
		Import_In iin;
		Import_Out iout;
		EVP_PKEY *pkey;
		TPMT_SENSITIVE s;
		TPM2B_NAME name;

		/* may be needed to decrypt the key */
		OpenSSL_add_all_ciphers();
		pkey = openssl_read_key(wrap);
		if (!pkey) {
			reason = "unable to read key";
			goto out_delete;
		}

		iin.parentHandle = phandle;

		rc = RAND_bytes(iin.encryptionKey.t.buffer, T2_AES_KEY_BYTES);
		if (!rc) {
			reason = "Can't get a random AES key for parameter encryption";
			goto out_delete;
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
		/* set the NODA flag */
		iin.objectPublic.publicArea.objectAttributes.val |= noda;
		rc = tpm2_ObjectPublic_GetName(&name,
					       &iin.objectPublic.publicArea);
		if (rc) {
			reason = "tpm2_ObjectPublic_GetName";
			goto out_flush;
		}

		rc = tpm2_SensitiveToDuplicate(&s, &name, name_alg, NULL,
					       &iin.symmetricAlg,
					       &iin.encryptionKey,
					       &iin.duplicate);
		if (rc) {
			reason = "tpm2_SensitiveToDuplicate";
			goto out_flush;
		}

		/* use salted parameter encryption to hide the key */
		rc = tpm2_get_hmac_handle(tssContext, &authHandle, phandle);
		if (rc)
			goto out_flush;

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
		Create_In cin;
		Create_Out cout;

		if (rsa) {
			tpm2_public_template_rsa(&cin.inPublic.publicArea);
			cin.inPublic.publicArea.parameters.rsaDetail.keyBits = key_size;
			cin.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
			cin.inPublic.publicArea.unique.rsa.t.size = 0;

		} else {
			tpm2_public_template_ecc(&cin.inPublic.publicArea, ecc);
		}

		cin.inPublic.publicArea.objectAttributes.val |=
			noda |
			TPMA_OBJECT_SENSITIVEDATAORIGIN;
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
		rc = tpm2_get_hmac_handle(tssContext, &authHandle, phandle);
		if (rc)
			goto out_flush;

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
	buffer = pubkey;
	pubkey_len = 0;
	size = sizeof(pubkey);
	TSS_TPM2B_PUBLIC_Marshal(pub, &pubkey_len, &buffer, &size);
	buffer = privkey;
	privkey_len = 0;
	size = sizeof(privkey);
	TSS_TPM2B_PRIVATE_Marshal(priv, &privkey_len, &buffer, &size);
	openssl_write_tpmfile(filename, pubkey, pubkey_len, privkey, privkey_len, auth == NULL, parent);
	TSS_Delete(tssContext);
	tpm2_rm_tssdir(dir, 0);

	exit(0);

 out_flush:
	tpm2_flush_srk(tssContext, phandle);
 out_delete:
	TSS_Delete(tssContext);
	rmdir(dir);
 out_err:
	tpm2_error(rc, reason);

	exit(1);
}
