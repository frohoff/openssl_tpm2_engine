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

static struct option long_options[] = {
	{"auth-parent", 1, 0, 'b'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{"password", 1, 0, 'k'},
	{0, 0, 0, 0}
};

void
usage(char *argv0)
{
	fprintf(stdout, "Usage: %s [options] <filename>\n\n"
		"Options:\n"
		"\t-b, --auth-parent <pwd>       Specify the parent key password\n"
		"\t                              (default EmptyAuth)\n"
		"\t-h, --help                    print this help message\n"
		"\t-v, --version                 print package version\n"
		"\t-k, --password <pwd>          use this password instead of prompting\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

static int ui_read(UI *ui, UI_STRING *uis)
{
	char password[128];
	const char *pwd = UI_get0_user_data(ui);

	if (UI_get_string_type(uis) != UIT_PROMPT)
		return 0;

	if (!pwd || pwd[0] == '\0') {
		pwd = password;
		EVP_read_pw_string(password, sizeof(password), "TPM Sealed Data Passphrase:", 0);
	}
	UI_set_result(ui, uis, pwd);
	return 1;
}

int main(int argc, char **argv)
{
	int option_index, c;
	char *parent_auth = NULL, *pass = NULL;
	char *filename;
	TPM_RC rc;
	TSS_CONTEXT *tssContext;
	const char *reason;
	TPM_HANDLE itemHandle;
	SENSITIVE_DATA_2B outData;
	uint32_t parent, session;
	UI_METHOD *ui = UI_create_method("unseal");
	struct app_data *app_data;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "k:b:hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
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
		case 'v':
			fprintf(stdout, "%s " VERSION "\n"
				"Copyright 2017 by James Bottomley\n"
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
	if (optind >= argc) {
		printf("Too few arguments: Expected file name as last argument\n");
		usage(argv[0]);
	}

	filename = argv[argc - 1];

	if (optind < argc - 1) {
		printf("Unexpected additional arguments\n");
		usage(argv[0]);
	}

	if (!ui) {
		fprintf(stderr, "Failed to allocate UI\n");
		exit(1);
	}

	UI_method_set_reader(ui, ui_read);
	rc = tpm2_load_engine_file(filename, &app_data, NULL,
				   ui, pass, parent_auth, 1, 0);
	if (!rc) {
		reason = "tpm2_engine_load_file";
		rc = NOT_TPM_ERROR;
		goto err;
	}

	rc = tpm2_load_key(&tssContext, app_data, parent_auth,
			   &parent);
	if (!rc) {
		reason = "tpm2_load_key";
		rc = NOT_TPM_ERROR;
		goto out_free_app_data;
	}

	itemHandle = rc;

	rc = tpm2_get_session_handle(tssContext, &session, parent,
				     app_data->req_policy_session ?
				     TPM_SE_POLICY : TPM_SE_HMAC,
				     name_alg);
	tpm2_flush_handle(tssContext, parent);
	if (rc) {
		reason = "tpm2_get_session_handle";
		goto out_flush_data;
	}

	if (app_data->req_policy_session) {
		rc = tpm2_init_session(tssContext, session,
				       app_data, name_alg);
		if (rc) {
			reason = "tpm2_init_session";
			goto out_flush_session;
		}
	}

	rc = tpm2_Unseal(tssContext, itemHandle, &outData, session,
			 app_data->auth);

	if (rc) {
		reason = "TPM2_Unseal";
	out_flush_session:
		tpm2_flush_handle(tssContext, session);
	} else {
		fwrite(outData.buffer, 1,
		       outData.size, stdout);
	}

 out_flush_data:
	tpm2_flush_handle(tssContext, itemHandle);
 out_free_app_data:
	TSS_Delete(tssContext);
	tpm2_delete(app_data);

 err:
	if (rc) {
		if (rc == NOT_TPM_ERROR)
			fprintf(stderr, "%s failed\n", reason);
		else
			tpm2_error(rc, reason);
		rc = 1;
	}
	exit(rc);
}
