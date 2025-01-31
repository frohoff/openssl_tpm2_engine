/*
 *
 *   Copyright (C) 2019 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 *   SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ui.h>

#include "tpm2-tss.h"
#include "tpm2-asn.h"
#include "tpm2-common.h"

#define OPT_SIGNED_POLICY 0x1fd
#define OPT_LOCALITY 0x1fc
#define OPT_SECRET 0x1fb

static struct option long_options[] = {
	{"auth", 0, 0, 'a'},
	{"auth-parent", 1, 0, 'b'},
	{"help", 0, 0, 'h'},
	{"parent-handle", 1, 0, 'p'},
	{"pcr-lock", 1, 0, 'x'},
	{"locality", 1, 0, OPT_LOCALITY },
	{"signed-policy", 1, 0, OPT_SIGNED_POLICY },
	{"secret", 1, 0, OPT_SECRET },
	{"version", 0, 0, 'v'},
	{"password", 1, 0, 'k'},
	{"da", 0, 0, 'd'},
	{"policy", 1, 0, 'c'},
	{"nomigrate", 0, 0, 'm'},
	{"name-scheme", 1, 0, 'n'},
	{"import", 1, 0, 'i'},
	{0, 0, 0, 0}
};

static void tpm2_public_template_seal(TPMT_PUBLIC *pub)
{
	pub->type = TPM_ALG_KEYEDHASH;
	pub->nameAlg = name_alg;
	VAL(pub->objectAttributes) =
		TPMA_OBJECT_USERWITHAUTH;
	VAL_2B(pub->authPolicy, size) = 0;
	pub->parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
	VAL_2B(pub->unique.sym, size) = 0;
}

void
usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-a, --auth                    The data blob requires authorization\n"
		"\t-b, --auth-parent <pwd>       Specify the parent key password\n"
		"\t                              (default EmptyAuth)\n"
		"\t-d, --da                      mark the key as having Dictionary Attack implications.  This means that if\n"
		"\t                              the key password is incorrectly presented too many times, the TPM may\n"
		"\t                              Implement DA mitigation and refuse connections for a while\n"
		"\t-h, --help                    print this help message\n"
		"\t-p, --parent-handle <handle>  parent for the key, can either be a\n"
		"\t                              persistent key or a hierarchy.\n"
		"\t                              the hierarchies can be 'platform',\n"
		"\t                              'owner', 'null' or 'endorsement'.\n"
		"\t                              The seeds used for derivation are\n"
		"\t                              platform, storage, null or endorsement\n"
		"\t                              respectively\n"
		"\t-v, --version                 print package version\n"
		"\t-k, --password <pwd>          use this password instead of prompting\n"
		"\t-m, --nomigrate                Create a sealed data bundle that can be\n"
		"                                migrated to other systems.\n"
		"\t-n, --name-scheme <scheme>    name algorithm to use sha1 [sha256] sha384 sha512\n"
		"\t-x, --pcr-lock <pcrs>         Lock the created key to the specified PCRs\n"
		"                                By current value.  See PCR VALUES for\n"
		"                                details about formatting\n"
		"\t--locality <loc>              Can only be unsealed in a set of localities\n"
		"                                described by the <loc> bitmap\n"
		"\t--signed-policy <key>         Add a signed policy directive that allows\n"
		"\t                              policies signed by the specified public <key>\n"
		"\t                              to authorize unsealing\n"
		"\t--secret <handle>             Tie authorization of the key to the\n"
		"\t                              Authorization of a different object\n"
		"\t                              Identified by <handle>.\n"
		"\t-i, --import <pubkey>         Create an importable key with the outer\n"
		"                                wrapper encrypted to <pubkey>\n"
		"\t-c, --policy                  Specify a policy for unsealing the data\n"
		"\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

void wrap_data(TPMT_SENSITIVE *s, const char *password, void *data,
	       int data_len)
{
	memset(s, 0, sizeof(*s));

	s->sensitiveType = TPM_ALG_KEYEDHASH;
	if (password) {
		int len = strlen(password);

		memcpy(VAL_2B(s->authValue, buffer), password, len);
		VAL_2B(s->authValue, size) = len;
	} else {
		VAL_2B(s->authValue, size) = 0;
	}
	VAL_2B(s->sensitive.bits, size) = data_len;
	memcpy(VAL_2B(s->sensitive.bits, buffer), data, data_len);
}

int main(int argc, char **argv)
{
	int option_index, c;
	int nomigrate = 0, parent = TPM_RH_OWNER;
	char *data_auth = NULL, *parent_auth = NULL, *pass = NULL;
	char *policyFilename = NULL;
	char *filename;
	uint32_t noda = TPMA_OBJECT_NODA, phandle;
	TPM_RC rc;
	TSS_CONTEXT *tssContext = NULL;
	const char *dir = NULL;
	const char *reason = ""; /* gcc 4.8.5 gives spurious uninitialized warning without this */
	TPMT_HA digest;
	uint32_t sizeInBytes;
	TPM_HANDLE authHandle, secret_handle = 0;
	STACK_OF(TSSOPTPOLICY) *sk = NULL;
	TPM2B_SENSITIVE_CREATE inSensitive;
	TPM2B_PUBLIC inPublic;
	PRIVATE_2B outPrivate;
	TPM2B_PUBLIC outPublic;

	TPMS_SENSITIVE_CREATE *s = &inSensitive.sensitive;
	TPMT_PUBLIC *p = &inPublic.publicArea;
	BYTE pubkey[sizeof(TPM2B_PUBLIC)];
	BYTE privkey[sizeof(PRIVATE_2B)];
	BYTE *buffer;
	int32_t size;
	uint16_t pubkey_len, privkey_len;
	char *parent_str = NULL;
	char *import = NULL;
	TPML_PCR_SELECTION pcr_lock;
	int has_policy = 0;
	char *signed_policy = NULL;
	ENCRYPTED_SECRET_2B secret, *enc_secret = NULL;
	int has_locality = 0, locality = 0;

	pcr_lock.count = 0;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "ak:b:hp:vdsun:i:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			data_auth = malloc(128);
			break;
		case 'k':
			pass = optarg;
			if (strlen(pass) > 127) {
				printf("password is too long\n");
				exit(1);
			}
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
		case 'v':
			fprintf(stdout, "%s " VERSION "\n"
				"Copyright 2017 by James Bottomley\n"
				"License LGPL-2.1-only\n"
				"Written by James Bottomley <James.Bottomley@HansenPartnership.com>\n",
				argv[0]);
			exit(0);
		case 'd':
			noda = 0;
			break;
		case 'c':
			policyFilename = optarg;
			break;
		case 'm':
			nomigrate = 1;
			break;
		case 'x':
			tpm2_get_pcr_lock(&pcr_lock, optarg);
			break;
		case 'i':
			import = optarg;
			break;
		case OPT_SIGNED_POLICY:
			signed_policy = optarg;
			break;
		case OPT_LOCALITY:
			has_locality = 1;
			locality = strtoul(optarg, NULL, 0);
			break;
		case OPT_SECRET:
			has_policy = 1;
			secret_handle = strtoul(optarg, NULL, 0);
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
			fprintf(stderr, "Failed to allocate policy stack\n");
			exit(1);
		}

		if (policyFilename) {
			rc = tpm2_parse_policy_file(policyFilename, sk,
						    data_auth, &digest);
			if (rc) {
				reason = "parse_policy_file";
				goto out_free_policy;
			}
		} else if (signed_policy) {
			rc = tpm2_add_signed_policy(sk, signed_policy, &digest);
			reason = "add_signed_policy";
			if (rc)
				goto out_free_policy;
		}
	}

	if (data_auth) {
		if (pass) {
			/* key length already checked */
			strcpy(data_auth, pass);
		} else {
			if (EVP_read_pw_string(data_auth, 128,
					       "Enter TPM key authority: ", 1)) {
				fprintf(stderr, "Passwords do not match\n");
				reason = "authorization";
				rc = NOT_TPM_ERROR;
				goto out_free_auth;
			}
		}
		if (has_policy && !policyFilename)
			tpm2_add_auth_policy(sk, &digest);
	}

	if (!import) {
		dir = tpm2_set_unique_tssdir();
		rc = tpm2_create(&tssContext, dir);
		if (rc) {
			reason = "TSS_Create";
			goto out_rmdir;
		}
		if (pcr_lock.count != 0) {
			rc = tpm2_pcr_lock_policy(tssContext, &pcr_lock,
						  sk, &digest);
			if (rc) {
				reason = "create pcr policy";
				goto out_free_auth;
			}
		}
		if (parent_str) {
			parent = tpm2_get_parent(tssContext, parent_str);
			if (parent == 0) {
				reason = "Invalid parent";
				goto out_delete;
			}
		}

		if (tpm2_handle_mso(tssContext, parent, TPM_HT_PERMANENT)) {
			rc = tpm2_load_srk(tssContext, &phandle, parent_auth,
					   NULL, parent, 1);
			if (rc) {
				reason = "tpm2_load_srk";
				goto out_delete;
			}
		} else {
			phandle = parent;
		}
	}

	if (has_locality)
		tpm2_add_locality(sk, locality, &digest);

	if (secret_handle)
		tpm2_add_policy_secret(tssContext, sk, secret_handle, &digest);

	tpm2_public_template_seal(p);

	if (has_policy) {
		VAL(p->objectAttributes) &=
			~TPMA_OBJECT_USERWITHAUTH;
		rc = TSS_TPM2B_Create(
			(TPM2B *)&p->authPolicy,
			(uint8_t *)&digest.digest, sizeInBytes,
			sizeof(TPMU_HA));
		if (rc) {
			reason = "set policy";
			goto out_flush;
		}
	}

	memset(s, 0, sizeof(*s));
	if (data_auth) {
		int len = strlen(data_auth);
		memcpy(VAL_2B(s->userAuth, buffer), data_auth, len);
		VAL_2B(s->userAuth, size) = len;
	}
	VAL_2B(s->data, size) = fread(VAL_2B(s->data, buffer), 1,
				      MAX_SYM_DATA, stdin);

	/* set the NODA flag */
	VAL(p->objectAttributes) |= noda;

	if (nomigrate)
		VAL(p->objectAttributes) |=
			TPMA_OBJECT_FIXEDPARENT |
			TPMA_OBJECT_FIXEDTPM;

	if (import) {
		TPMT_SENSITIVE ts;
		EVP_PKEY *p_pkey = openssl_read_public_key(import);
		if (parent_str) {
			parent = tpm2_get_parent_ext(parent_str);
			if (!parent) {
				fprintf(stderr, "Unknown parent '%s'\n",
					parent_str);
				goto out_flush;
			}
		} else {
			parent = EXT_TPM_RH_OWNER;
		}

		wrap_data(&ts, data_auth, VAL_2B(s->data, buffer),
			  VAL_2B(s->data, size));

		/* random nonce for seed to add entropy to wrapping */
		VAL_2B(ts.seedValue, size) = TSS_GetDigestSize(name_alg);
		RAND_bytes(VAL_2B(ts.seedValue, buffer),
			   VAL_2B(ts.seedValue, size));

		/* fill in the unique area as Hash(seed||key) */
		digest.hashAlg = name_alg;
		TSS_Hash_Generate(&digest,
				  VAL_2B(ts.seedValue, size),
				  VAL_2B(ts.seedValue, buffer),
				  VAL_2B(ts.sensitive.bits, size),
				  VAL_2B(ts.sensitive.bits, buffer),
				  0, NULL);
		VAL_2B(p->unique.keyedHash, size) = TSS_GetDigestSize(name_alg);
		memcpy(VAL_2B(p->unique.keyedHash, buffer),
		       &digest.digest, VAL_2B(p->unique.keyedHash, size));

		outPublic = inPublic;
		rc = tpm2_outerwrap(p_pkey, &ts, &outPublic.publicArea, &outPrivate, &secret);
		if (rc)
			goto out_flush;
		enc_secret = &secret;
		goto write_file;
	}
	/* use salted parameter encryption to hide the key */
	rc = tpm2_get_session_handle(tssContext, &authHandle, phandle,
					     TPM_SE_HMAC, name_alg);
	if (rc) {
		reason = "get session handle";
		goto out_flush;
	}

	rc = tpm2_Create(tssContext, phandle, &inSensitive, &inPublic,
			 &outPrivate, &outPublic, authHandle, parent_auth);

	if (rc) {
		reason = "TPM2_Create";
		/* failure means auth handle is not flushed */
		tpm2_flush_handle(tssContext, authHandle);
		goto out_flush;
	}

	parent = tpm2_handle_ext(tssContext, parent);

 write_file:
	buffer = pubkey;
	pubkey_len = 0;
	size = sizeof(pubkey);
	TSS_TPM2B_PUBLIC_Marshal(&outPublic, &pubkey_len,
				 &buffer, &size);
	buffer = privkey;
	privkey_len = 0;
	size = sizeof(privkey);
	TSS_TPM2B_PRIVATE_Marshal((TPM2B_PRIVATE *)&outPrivate, &privkey_len,
				  &buffer, &size);
	tpm2_write_tpmfile(filename, pubkey, pubkey_len,
			   privkey, privkey_len,
			   data_auth == NULL && secret_handle == 0,
			   parent, sk, 2, enc_secret);

 out_flush:
	if (tssContext)
		tpm2_flush_srk(tssContext, phandle);
 out_delete:
	if (tssContext)
		TSS_Delete(tssContext);
 out_rmdir:
	if (dir)
		rmdir(dir);
 out_free_auth:
	free(data_auth);
 out_free_policy:
	tpm2_free_policy(sk);

	if (rc) {
		if (rc == NOT_TPM_ERROR)
			fprintf(stderr, "%s failed\n", reason);
		else
			tpm2_error(rc, reason);
		rc = 1;
	}
	exit(rc);
}
