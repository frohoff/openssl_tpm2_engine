/*
 *
 *   Copyright (C) 2022 James Bottomley <James.Bottomley@HansenPartnership.com>
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

#define OPT_SIGNED_POLICY 0x1fd

static struct option long_options[] = {
	{"auth", 0, 0, 'a'},
	{"help", 0, 0, 'h'},
	{"pcr-lock", 1, 0, 'x'},
	{"signed-policy", 1, 0, OPT_SIGNED_POLICY },
	{"version", 0, 0, 'v'},
	{"key-policy", 1, 0, 'c'},
	{"engine", 1, 0, 'e'},
	{"policy-name", 1, 0, 'n'},
	{0, 0, 0, 0}
};

void
usage(char *argv0)
{
	fprintf(stdout, "Usage: %s <cmd> [options] <tpmkey> [<arg>]\n\n"
		"Options:\n"
		"\t-a, --auth                    require a password for the key [NO]\n"
		"\t-h, --help                    print this help message\n"
		"\t-c, --key-policy <pubkey>     Specify a policy for the TPM key\n"
		"\t-i, --import <pubkey>         Create an importable key with the outer\n"
		"                                wrapper encrypted to <pubkey>\n"
		"\t-x, --pcr-lock <pcrs>         Lock the created key to the specified PCRs\n"
		"                                By current value.  See PCR VALUES for\n"
		"                                details about formatting\n"
		"\n"
		"\t--signed-policy <key>         Add a signed policy directive that allows\n"
		"\t                              policies signed by the specified public <key>\n"
		"\t                              to authorize use of the key\n"
		"\t-n, --policy-name <name>      Optional name to annotate the policy with\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

static TPM_ALG_ID
tpm2_get_name_alg(const char *tpmkey)
{
	BIO *bf;
	TSSPRIVKEY *tpk;
	BYTE *buffer;
	INT32 size;
	TPM2B_PUBLIC pub;

	bf = BIO_new_file(tpmkey, "r");
	if (!bf) {
		fprintf(stderr, "File %s does not exist or cannot be read\n",
			tpmkey);
		exit(1);
	}

	tpk = PEM_read_bio_TSSPRIVKEY(bf, NULL, NULL, NULL);
	if (!tpk) {
		BIO_seek(bf, 0);
		ERR_clear_error();
		tpk = ASN1_item_d2i_bio(ASN1_ITEM_rptr(TSSPRIVKEY), bf, NULL);
	}
	BIO_free(bf);
	if (!tpk) {
		fprintf(stderr, "Cannot parse file as TPM key\n");
		exit(1);
	}
	buffer = tpk->pubkey->data;
	size = tpk->pubkey->length;
	TPM2B_PUBLIC_Unmarshal(&pub, &buffer, &size, FALSE);
	return pub.publicArea.nameAlg;
}

int main(int argc, char **argv)
{
	char *filename, *policyFilename = NULL, *policy_name = NULL,
		*policy_signing_key;
	int option_index, c, auth = 0;
	const char *reason = NULL;
	TPM_RC rc;
	char *engine = NULL;
	char *signed_policy = NULL;
	TSSAUTHPOLICY *ap = NULL;
	TPMT_HA digest;
	int size;
	TPML_PCR_SELECTION pcr_lock = { 0 };

	OpenSSL_add_all_digests();
	/* may be needed to decrypt the key */
	OpenSSL_add_all_ciphers();

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "ahvc:x:e:n:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				auth = 1;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				fprintf(stdout, "%s " VERSION "\n"
					"Copyright 2017 by James Bottomley\n"
					"License LGPL-2.1-only\n"
					"Written by James Bottomley <James.Bottomley@HansenPartnership.com>\n",
					argv[0]);
				exit(0);
			case 'c':
				policyFilename = optarg;
				break;
			case 'x':
				tpm2_get_pcr_lock(&pcr_lock, optarg);
				break;
			case 'e':
				engine = optarg;
				break;
			case 'n':
				policy_name = optarg;
				break;
			case OPT_SIGNED_POLICY:
				signed_policy = optarg;
				break;
			default:
				printf("Unknown option '%c'\n", c);
				usage(argv[0]);
				break;
		}
	}

	if (optind >= argc - 1) {
		printf("Too few arguments: Expected file name as last argument\n");
		usage(argv[0]);
	}

	filename = argv[argc - 2];
	policy_signing_key = argv[argc - 1];

	if (optind < argc - 2) {
		printf("Unexpected additional arguments\n");
		usage(argv[0]);
	}

	name_alg = tpm2_get_name_alg(filename);
	digest.hashAlg = name_alg;
	size  = TSS_GetDigestSize(digest.hashAlg);
	memset((uint8_t *)&digest.digest, 0, size);

	ap = TSSAUTHPOLICY_new();
	if (policy_name) {
		ap->name = ASN1_UTF8STRING_new();
		ASN1_STRING_set(ap->name, policy_name, strlen(policy_name));
	}
	ap->policy = sk_TSSOPTPOLICY_new_null();
	if (!ap->policy) {
		rc = NOT_TPM_ERROR;
		reason="sk_TSSOPTPOLICY_new_null allocation";
		goto out_err;
	}

	if (policyFilename) {
		rc = tpm2_parse_policy_file(policyFilename, ap->policy,
					    (char *)(unsigned long)auth,
					    &digest);
		reason = "parse_policy_file";
		if (rc)
			goto out_free_policy;
	} else if (signed_policy) {
		rc = tpm2_add_signed_policy(ap->policy, signed_policy, &digest);
		reason = "add_signed_policy";
		if (rc)
			goto out_free_policy;
	}

	if (auth)
		tpm2_add_auth_policy(ap->policy, &digest);

	if (pcr_lock.count != 0) {
		TSS_CONTEXT *tssContext = NULL;
		const char *dir;

		dir = tpm2_set_unique_tssdir();
		rc = tpm2_create(&tssContext, dir);
		if (rc) {
			reason = "TSS_Create";
			goto out_free_policy;
		}
		rc = tpm2_pcr_lock_policy(tssContext, &pcr_lock,
					  ap->policy, &digest);
		TSS_Delete(tssContext);
		tpm2_rm_tssdir(dir);
		if (rc) {
			reason = "create pcr policy";
			goto out_free_policy;
		}
	}

	rc = tpm2_new_signed_policy(filename, policy_signing_key, engine,
				    ap, &digest);
	if (rc == 0)
		exit(0);

 out_free_policy:
	if (ap->name)
		ASN1_UTF8STRING_free(ap->name);
	tpm2_free_policy(ap->policy);
 out_err:
	if (rc == NOT_TPM_ERROR)
		fprintf(stderr, "%s failed\n", reason);
	else
		tpm2_error(rc, reason);

	exit(1);
}
