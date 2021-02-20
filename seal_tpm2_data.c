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
#include <openssl/ui.h>

#include "tpm2-tss.h"
#include "tpm2-asn.h"
#include "tpm2-common.h"

static TPM_ALG_ID name_alg = TPM_ALG_SHA256;

static struct option long_options[] = {
	{"auth", 0, 0, 'a'},
	{"auth-parent", 1, 0, 'b'},
	{"help", 0, 0, 'h'},
	{"parent-handle", 1, 0, 'p'},
	{"version", 0, 0, 'v'},
	{"password", 1, 0, 'k'},
	{"da", 0, 0, 'd'},
	{"policy", 1, 0, 'c'},
	{"nomigrate", 0, 0, 'm'},
	{"name-scheme", 1, 0, 'n'},
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
		"\t-m,--nomigrate                Create a sealed data bundle that can be\n"
		"                                migrated to other systems.\n"
		"\t-n, --name-scheme <scheme>    name algorithm to use sha1 [sha256] sha384 sha512\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
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
	TSS_CONTEXT *tssContext;
	const char *dir;
	const char *reason = ""; /* gcc 4.8.5 gives spurious uninitialized warning without this */
	TPMT_HA digest;
	uint32_t sizeInBytes;
	TPM_HANDLE authHandle;
	STACK_OF(TSSOPTPOLICY) *sk = NULL;
	Create_In cin;
	Create_Out cout;
	TPMS_SENSITIVE_CREATE *s = &cin.inSensitive.sensitive;
	TPMT_PUBLIC *p = &cin.inPublic.publicArea;
	BYTE pubkey[sizeof(TPM2B_PUBLIC)];
	BYTE privkey[sizeof(PRIVATE_2B)];
	BYTE *buffer;
	int32_t size;
	uint16_t pubkey_len, privkey_len;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "ak:b:hp:vdsun",
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
			parent = tpm2_get_parent(optarg);
				if (parent == 0) {
					fprintf(stderr, "Invalid parent %s\n", optarg);
					exit(1);
				}
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

	digest.hashAlg = name_alg;
	sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	memset((uint8_t *)&digest.digest, 0, sizeInBytes);

	if (policyFilename) {
		sk = sk_TSSOPTPOLICY_new_null();
		if (!sk) {
			fprintf(stderr, "Failed to allocate policy stack\n");
			exit(1);
		}

		rc = tpm2_parse_policy_file(policyFilename, sk,
					    data_auth, &digest);
		if (rc) {
			reason = "parse_policy_file";
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
	}

	dir = tpm2_set_unique_tssdir();
	rc = tpm2_create(&tssContext, dir);
	if (rc) {
		reason = "TSS_Create";
		goto out_rmdir;
	}

	if ((parent & 0xff000000) == 0x40000000) {
		rc = tpm2_load_srk(tssContext, &phandle, parent_auth,
				   NULL, parent, 1);
		if (rc) {
				reason = "tpm2_load_srk";
				goto out_delete;
		}
	} else {
		phandle = parent;
	}

	tpm2_public_template_seal(p);

	cin.parentHandle = phandle;
	VAL_2B(cin.outsideInfo, size) = 0;
	cin.creationPCR.count = 0;

	if (policyFilename) {
		p->objectAttributes.val &=
			~TPMA_OBJECT_USERWITHAUTH;
		rc = TSS_TPM2B_Create(
			&p->authPolicy.b,
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

	buffer = pubkey;
	pubkey_len = 0;
	size = sizeof(pubkey);
	TSS_TPM2B_PUBLIC_Marshal(&cout.outPublic, &pubkey_len,
				 &buffer, &size);
	buffer = privkey;
	privkey_len = 0;
	size = sizeof(privkey);
	TSS_TPM2B_PRIVATE_Marshal(&cout.outPrivate, &privkey_len,
				  &buffer, &size);
	tpm2_write_tpmfile(filename, pubkey, pubkey_len,
			   privkey, privkey_len, data_auth == NULL,
			   parent, sk, 2, NULL);


 out_flush:
	tpm2_flush_srk(tssContext, phandle);
 out_delete:
	TSS_Delete(tssContext);
 out_rmdir:
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
