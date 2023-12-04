/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/bio.h>

#include "tpm2-tss.h"
#include "tpm2-asn.h"
#include "tpm2-common.h"

extern char *srk_auth;
extern char *nvprefix;

/* core context functions in provider.h */
void *tpm2_passthrough_newctx(void *ctx);
void tpm2_passthrough_freectx(void *ctx);
int tpm2_get_sizes(const struct app_data *ad, int *bits, int *security,
		   int *size);

/* decode_encode.c */
extern const OSSL_ALGORITHM encoders[];
extern const OSSL_ALGORITHM decoders[];

/* keymgmt.c */

extern const OSSL_ALGORITHM keymgmts[];

void *tpm2_keymgmt_new(void *pctx); /* needed by decode_encode.c */
void tpm2_keymgmt_free(void *ref);  /* needed by decryption.c */

/* signatures.c */

extern const OSSL_ALGORITHM signatures[];

/* decryption.c */

extern const OSSL_ALGORITHM asymciphers[];
extern const OSSL_ALGORITHM keyexchs[];

/* store.c */

extern OSSL_ALGORITHM stores[];


#endif
