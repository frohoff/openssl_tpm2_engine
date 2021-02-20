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

#include "tpm2-tss.h"
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
	int option_index, c;
	int force = 0;
	TSS_CONTEXT *tssContext;
	TPM_RC rc;
	TPM_HANDLE objectHandle;
	char *auth = NULL;
	int ret = 1;
	struct app_data *app_data;

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

	ret = tpm2_load_engine_file(filename, &app_data, NULL, NULL, NULL,
				    auth, 0, 0);
	if (!ret) {
		fprintf(stderr, "Failed to parse file %s\n", filename);
		exit(1);
	}
	if (app_data->commands && !force) {
		fprintf(stderr, "NUM COMMANDS=%d\n", app_data->num_commands);
		fprintf(stderr, "Warning: key %s has associated policy\n"
			"Policy keys are hard to use, specify --force if this is really what you want\n",
			filename);
		ret = 1;
		goto out_free;
	}

	ret = tpm2_load_key(&tssContext, app_data, auth, NULL);
	if (!ret) {
		ret = 1;
		goto out;
	};

	objectHandle = ret;
	ret = 1;		/* set up error return */
	rc = tpm2_EvictControl(tssContext, objectHandle, nvindex);
	if (rc)
		tpm2_error(rc, "TPM2_EvictControl");
	else
		ret = 0;

	tpm2_flush_handle(tssContext, objectHandle);

 out:
	TSS_Delete(tssContext);
 out_free:
	tpm2_rm_keyfile(app_data->dir, nvindex);
	tpm2_delete(app_data);
	exit(ret);
}
