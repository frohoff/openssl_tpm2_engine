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
#include <fcntl.h>
#include <ctype.h>

#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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

/* for use as a TPM_RC return type to indicate this is
 * not a TPM error, so don't process the rc as one */
#define NOT_TPM_ERROR (0xffffffff)

static struct option long_options[] = {
	{"auth-parent", 1, 0, 'b'},
	{"force", 0, 0, 'f'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{0, 0, 0, 0}
};

void
usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename> <nvindex>\n\n"
		"Options:\n"
		"\t-b, --auth-parent <pwd>       Specify the parent key password\n"
		"\t                              (default EmptyAuth)\n"
		"\t-f, --force                   force loading of key with policy\n"
		"\t-h, --help                    print this help message\n"
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

int main(int argc, char **argv)
{
	char *filename;
	TPM_HANDLE nvindex;
	const char *tssdir;
	TSSPRIVKEY *tpk;
	BIO *bf;
	int option_index, c;
	int force = 0;
	TSS_CONTEXT *tssContext;
	TPM_RC rc;
	Load_In lin;
	Load_Out lout;
	EvictControl_In ein;
	BYTE *buffer;
	INT32 size;
	char *auth = NULL;
	TPM_HANDLE session, parent;
	int ret = 1;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "b:fhv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			force = 1;
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'b':
			auth = optarg;
			break;
		case 'v':
			fprintf(stdout, "%s " VERSION "\n"
				"Copyright 2019 by James Bottomley\n"
				"License LGPL-2.1-only\n"
				"Written by James Bottomley <James.Bottomley@HansenPartnership.com>\n",
				argv[0]);
			exit(0);
		default:
			printf("Unknown option '%c'\n", c);
			usage(argv[0]);
			break;
		}
	}
	if (optind >= argc - 1) {
		printf("Too few arguments: Expected filename and nvindex");
		usage(argv[0]);
	}

	filename = argv[argc - 2];
	nvindex = strtoul(argv[argc - 1], NULL, 16);

	if (optind < argc - 2) {
		printf("Unexpected additional arguments\n");
		usage(argv[0]);
	}

	if ((nvindex & 0xff000000) != 0x81000000) {
		printf("nvindex must have MSO 81\n");
		exit(1);
	}

	bf = BIO_new_file(filename, "r");
	if (!bf) {
		fprintf(stderr, "File %s does not exist or cannot be read\n", filename); 
		exit(1);
	}
	tpk = PEM_read_bio_TSSPRIVKEY(bf, NULL, NULL, NULL);
	BIO_free(bf);

	if (!tpk) {
		fprintf(stderr, "Failed to parse file %s\n", filename);
		exit(1);
	}
	if (tpk->policy && !force) {
		fprintf(stderr, "Warning: key %s has associated policy\n"
			"Policy keys are hard to use, specify --force if this is really what you want\n",
			filename);
		goto out_free;
	}

	buffer = tpk->privkey->data;
	size = tpk->privkey->length;
	TPM2B_PRIVATE_Unmarshal(&lin.inPrivate, &buffer, &size);

	buffer = tpk->pubkey->data;
	size = tpk->pubkey->length;
	TPM2B_PUBLIC_Unmarshal(&lin.inPublic, &buffer, &size, FALSE);

	parent = ASN1_INTEGER_get(tpk->parent);
	TSSPRIVKEY_free(tpk);
	tssdir = tpm2_set_unique_tssdir();
	rc = tpm2_create(&tssContext, tssdir);
	if (rc) {
		tpm2_error(rc, "tpm2_create");
		exit(1);
	}

	if ((parent & 0xff000000) == 0x81000000) {
		lin.parentHandle = parent;
	} else {
		rc = tpm2_load_srk(tssContext, &lin.parentHandle, auth, NULL,
				   parent, 1);
		if (rc)
			goto out;
	}
	rc = tpm2_get_session_handle(tssContext, &session, lin.parentHandle,
				     TPM_SE_HMAC, TPM_ALG_SHA256);
	if (rc)
		goto out_flush_srk;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&lout,
			 (COMMAND_PARAMETERS *)&lin,
			 NULL,
			 TPM_CC_Load,
			 session, auth, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_Load");
		tpm2_flush_handle(tssContext, session);
	}
 out_flush_srk:
	tpm2_flush_srk(tssContext, lin.parentHandle);
	if (rc)
		goto out;

	ein.auth = TPM_RH_OWNER;
	ein.objectHandle = lout.objectHandle;
	ein.persistentHandle = nvindex;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&ein,
			 NULL,
			 TPM_CC_EvictControl,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc)
		tpm2_error(rc, "TPM2_EvictControl");
	else
		ret = 0;

	tpm2_flush_handle(tssContext, lout.objectHandle);

 out:
	TSS_Delete(tssContext);
	tpm2_rm_keyfile(tssdir, parent);
	tpm2_rm_keyfile(tssdir, nvindex);
	tpm2_rm_tssdir(tssdir);
	exit(ret);

 out_free:
	TSSPRIVKEY_free(tpk);
	exit(1);
}
