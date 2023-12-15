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
#define OPT_LOCALITY 0x1fc
#define OPT_SECRET 0x1fb

static struct option long_options[] = {
	{"auth", 0, 0, 'a'},
	{"help", 0, 0, 'h'},
	{"pcr-lock", 1, 0, 'x'},
	{"locality", 1, 0, OPT_LOCALITY },
	{"signed-policy", 1, 0, OPT_SIGNED_POLICY },
	{"secret", 1, 0, OPT_SECRET},
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
		"\t--locality <loc>              Can only be used in a set of localities\n"
		"                                described by the <loc> bitmap\n"
		"\t--signed-policy <key>         Add a signed policy directive that allows\n"
		"\t                              policies signed by the specified public <key>\n"
		"\t                              to authorize use of the key\n"
		"\t--secret <handle>             Tie authorization of the key to the\n"
		"\t                              Authorization of a different object\n"
		"\t                              Identified by <handle>.\n"
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
	int option_index, c, auth = 0, i;
	const char *reason = NULL;
	TPM_RC rc;
	char *engine = NULL;
	char *signed_policy = NULL;
	TSSAUTHPOLICY *ap = NULL;
	TPMT_HA digest;
	int size;
	TPML_PCR_SELECTION pcr_lock = { 0 };
	int has_locality = 0;
	int locality = 0;
	int secret_handle = 0;
	STACK_OF(TSSAUTHPOLICY) *sk;
	enum cmd {
		CMD_ADD = 0,
		CMD_LS,
		CMD_RM,
		CMD_MAX
	} cmd;
	static char *command[] = {
		[CMD_ADD] = "add",
		[CMD_LS] = "ls",
		[CMD_RM] = "rm",
	};
	char *argv0 = argv[0];

	OpenSSL_add_all_digests();
	/* may be needed to decrypt the key */
	OpenSSL_add_all_ciphers();

	if (argc < 2)
		usage(argv0);

	for (cmd = CMD_ADD; cmd < CMD_MAX; cmd++)
		if (strcmp(argv[1], command[cmd]) == 0)
			break;
	if (cmd == CMD_MAX) {
		fprintf(stderr, "Unknown command %s\n", argv[1]);
		usage(argv0);
	}
	argc--;
	argv++;

	while (cmd == CMD_ADD) {
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
				usage(argv0);
				break;
			case 'v':
				fprintf(stdout, "%s " VERSION "\n"
					"Copyright 2017 by James Bottomley\n"
					"License LGPL-2.1-only\n"
					"Written by James Bottomley <James.Bottomley@HansenPartnership.com>\n",
					argv0);
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
			case OPT_LOCALITY:
				has_locality = 1;
				locality = strtol(optarg, NULL, 0);
				break;
			case OPT_SECRET:
				secret_handle = strtol(optarg, NULL, 0);
				break;
			default:
				printf("Unknown option '%c'\n", c);
				usage(argv0);
				break;
		}
	}

	if (((cmd == CMD_RM || cmd == CMD_ADD) && optind != argc - 2) ||
	    (cmd == CMD_LS && optind != argc - 1)) {
		fprintf(stderr, "Incorrect number of arguments\n");
		usage(argv0);
	}

	if (has_locality && locality == 0) {
		fprintf(stderr, "zero is an illegal locality bitmap\n");
		exit(1);
	}

	switch(cmd) {
	case CMD_ADD:
		filename = argv[argc - 2];
		policy_signing_key = argv[argc - 1];

		if (optind < argc - 2) {
			printf("Unexpected additional arguments\n");
			usage(argv0);
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

		if (has_locality)
			tpm2_add_locality(ap->policy, locality, &digest);

		if (secret_handle) {
			TSS_CONTEXT *tssContext = NULL;
			const char *dir;

			dir = tpm2_set_unique_tssdir();
			rc = tpm2_create(&tssContext, dir);
			if (rc) {
				reason = "TSS_Create";
				goto out_free_policy;
			}

			rc = tpm2_add_policy_secret(tssContext, ap->policy,
						    secret_handle, &digest);
			TSS_Delete(tssContext);
			tpm2_rm_tssdir(dir);
			if (rc) {
				reason = "create object authorization policy";
				goto out_free_policy;
			}
		}


		rc = tpm2_new_signed_policy(filename, policy_signing_key,
					    engine, ap, &digest,
					    auth || secret_handle);
		if (rc == 0)
			exit(0);

		/* tpm2_new_signed_policy frees the key which includes the policy */
		goto out_err;

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

	case CMD_LS:
		filename = argv[argc - 1];

		rc = tpm2_get_signed_policy(filename, &sk);
		if (rc)
			exit(1);
		if (!sk || sk_TSSAUTHPOLICY_num(sk) <=0 ) {
			printf("Key has no signed policies\n");
			sk_TSSAUTHPOLICY_free(sk);
			exit(0);
		}
		printf("Policy  Name\n");
		for (i = 0; i < sk_TSSAUTHPOLICY_num(sk); i++) {
			TSSAUTHPOLICY *ap = sk_TSSAUTHPOLICY_value(sk, i);
			int sz = ap->name ? ap->name->length : 0;
			char *name = ap->name ? (char *)ap->name->data : "";
			if (sz)
				printf("%6d  %*s\n", i+1, sz, name);
			else
				printf("%6d\n", i+1);
		}
		sk_TSSAUTHPOLICY_pop_free(sk, TSSAUTHPOLICY_free);
		exit(0);

	case CMD_RM:
		filename = argv[argc - 2];
		i = atoi(argv[argc - 1]);

		rc = tpm2_rm_signed_policy(filename, i);
		if (rc)
			exit(1);
		exit(0);

	case CMD_MAX:
		/* has to be here because stupid gcc doesn't notice
		 * the check above means it's impossible to get here*/
		;
	}
}
