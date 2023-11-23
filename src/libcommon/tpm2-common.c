/*
 * Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <arpa/inet.h>		/* htons */

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ui.h>
#include <openssl/rand.h>

#include "tpm2-tss.h"
#include "tpm2-asn.h"
#include "tpm2-common.h"

/* externally visible name algorithm (is only set once) */
TPM_ALG_ID name_alg = TPM_ALG_SHA256;

static struct {
	const char *hash;
	TPM_ALG_ID alg;
} tpm2_hashes[] = {
	{ "sha1", TPM_ALG_SHA1 },
	{ "sha256", TPM_ALG_SHA256 },
	{ "sha384", TPM_ALG_SHA384 },
#ifdef TPM_ALG_SHA512
	{ "sha512", TPM_ALG_SHA512 },
#endif
#ifdef TPM_ALG_SM3_256
	{ "sm3", TPM_ALG_SM3_256 },
#endif
	{ NULL, 0 }
};

#define		MAX_TPM_PCRS	24
const int	MAX_TPM_PCRS_ARRAY = (MAX_TPM_PCRS + 7)/8;

struct myTPM2B {
	UINT16 s;
	BYTE *const b;
};
struct tpm2_ECC_Curves {
	const char *name;
	int nid;
	TPMI_ECC_CURVE curve;
	/* 7 parameters are p, a, b, gX, gY, n, h */
	struct myTPM2B C[7];
};
/*
 * Mutually supported curves: curves both the TPM2 and
 * openssl support (this excludes BN P256)
 */
struct tpm2_ECC_Curves tpm2_supported_curves[] = {
	{ .name = "prime256v1",
	  .nid = NID_X9_62_prime256v1,
	  .curve = TPM_ECC_NIST_P256,
	  /* p */
	  .C[0].s = 32,
	  .C[0].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

		},
	  /* a */
	  .C[1].s = 32,
	  .C[1].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
		},
	  /* b */
	  .C[2].s = 32,
	  .C[2].b = (BYTE [])
		{
			0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
			0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
			0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
			0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
		},
	  /* gX */
	  .C[3].s = 32,
	  .C[3].b = (BYTE [])
		{
			0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
			0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
			0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
			0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
		},
	  /* gY */
	  .C[4].s = 32,
	  .C[4].b = (BYTE [])
		{
			0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
			0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
			0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
			0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
		},
	  /* order */
	  .C[5].s = 32,
	  .C[5].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
			0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
		},
	},
	{ .name = "secp384r1",
	  .nid = NID_secp384r1,
	  .curve = TPM_ECC_NIST_P384,
	  /* p */
	  .C[0].s = 48,
	  .C[0].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		},
	  /* a */
	  .C[1].s = 48,
	  .C[1].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC,

		},
	  /* b */
	  .C[2].s = 48,
	  .C[2].b = (BYTE [])
		{
			0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
			0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
			0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
			0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
			0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
			0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF,
		},
	  /* gX */
	  .C[3].s = 48,
	  .C[3].b = (BYTE [])
		{
			0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37,
			0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
			0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
			0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
			0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C,
			0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7,
		},
	  /* gY */
	  .C[4].s = 48,
	  .C[4].b = (BYTE [])
		{
			0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f,
			0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
			0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
			0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
			0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d,
			0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
		},
	  /* order */
	  .C[5].s = 48,
	  .C[5].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
			0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
			0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,
		},
	},
	{ .name = "secp521r1",
	  .nid = NID_secp521r1,
	  .curve = TPM_ECC_NIST_P521,
	  /* p */
	  .C[0].s = 66,
	  .C[0].b = (BYTE [])
		{
			0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF,
		},
	  /* a */
	  .C[1].s = 66,
	  .C[1].b = (BYTE [])
		{
			0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFC,
		},
	  /* b */
	  .C[2].s = 66,
	  .C[2].b = (BYTE [])
		{
			0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C,
			0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85,
			0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3,
			0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1,
			0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E,
			0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1,
			0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C,
			0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50,
			0x3F, 0x00,
		},
	  /* gX */
	  .C[3].s = 66,
	  .C[3].b = (BYTE [])
		{
			0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04,
			0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66, 0x23, 0x95,
			0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F,
			0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D,
			0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7,
			0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF,
			0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A,
			0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5,
			0xBD, 0x66,
		},
	  /* gY */
	  .C[4].s = 66,
	  .C[4].b = (BYTE [])
		{
			0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b,
			0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c, 0x7d,
			0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b,
			0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e,
			0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4,
			0x26, 0x40, 0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad,
			0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72,
			0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1,
			0x66, 0x50,
		},
	  /* order */
	  .C[5].s = 66,
	  .C[5].b = (BYTE [])
		{
			0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F,
			0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
			0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C,
			0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
			0x64, 0x09
		},
	},
	/* openssl unknown algorithms below */
	{ .name = "bnp256",
	  .nid = 0,
	  .curve = TPM_ECC_BN_P256,
	  /* p */
	  .C[0].s = 32,
	  .C[0].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
			0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9F,
			0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x98, 0x0A, 0x82,
			0xD3, 0x29, 0x2D, 0xDB, 0xAE, 0xD3, 0x30, 0x13,

		},
	  /* a */
	  .C[1].s = 1 ,
	  .C[1].b = (BYTE [])
		{
			0x00,
		},
	  /* b */
	  .C[2].s = 1,
	  .C[2].b = (BYTE [])
		{
			0x03,
		},
	  /* gX */
	  .C[3].s = 1 ,
	  .C[3].b = (BYTE [])
		{
			0x01,
		},
	  /* gY */
	  .C[4].s = 1 ,
	  .C[4].b = (BYTE [])
		{
			0x02,
		},
	  /* order */
	  .C[5].s = 32,
	  .C[5].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
			0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E,
			0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A,
			0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0D,
		},
	},
	{ .name = "bnp638",
	  .nid = 0,
	  .curve = TPM_ECC_BN_P638,
	  /* p */
	  .C[0].s = 80,
	  .C[0].b = (BYTE [])
		{
			0x23, 0xFF, 0xFF, 0xFD, 0xC0, 0x00, 0x00, 0x0D,
			0x7F, 0xFF, 0xFF, 0xB8, 0x00, 0x00, 0x01, 0xD3,
			0xFF, 0xFF, 0xF9, 0x42, 0xD0, 0x00, 0x16, 0x5E,
			0x3F, 0xFF, 0x94, 0x87, 0x00, 0x00, 0xD5, 0x2F,
			0xFF, 0xFD, 0xD0, 0xE0, 0x00, 0x08, 0xDE, 0x55,
			0xC0, 0x00, 0x86, 0x52, 0x00, 0x21, 0xE5, 0x5B,
			0xFF, 0xFF, 0xF5, 0x1F, 0xFF, 0xF4, 0xEB, 0x80,
			0x00, 0x00, 0x00, 0x4C, 0x80, 0x01, 0x5A, 0xCD,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEC, 0xE0,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67
		},
	  /* a */
	  .C[1].s = 1 ,
	  .C[1].b = (BYTE [])
		{
			0x00,
		},
	  /* b */
	  .C[2].s = 2,
	  .C[2].b = (BYTE [])
		{
			0x01, 0x01,
		},
	  /* gX */
	  .C[3].s = 80,
	  .C[3].b = (BYTE [])
		{
			0x23, 0xFF, 0xFF, 0xFD, 0xC0, 0x00, 0x00, 0x0D,
			0x7F, 0xFF, 0xFF, 0xB8, 0x00, 0x00, 0x01, 0xD3,
			0xFF, 0xFF, 0xF9, 0x42, 0xD0, 0x00, 0x16, 0x5E,
			0x3F, 0xFF, 0x94, 0x87, 0x00, 0x00, 0xD5, 0x2F,
			0xFF, 0xFD, 0xD0, 0xE0, 0x00, 0x08, 0xDE, 0x55,
			0xC0, 0x00, 0x86, 0x52, 0x00, 0x21, 0xE5, 0x5B,
			0xFF, 0xFF, 0xF5, 0x1F, 0xFF, 0xF4, 0xEB, 0x80,
			0x00, 0x00, 0x00, 0x4C, 0x80, 0x01, 0x5A, 0xCD,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEC, 0xE0,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66,
		},
	  /* gY */
	  .C[4].s = 1,
	  .C[4].b = (BYTE [])
		{
			0x010,
		},
	  /* order */
	  .C[5].s = 80,
	  .C[5].b = (BYTE [])
		{
			0x23, 0xFF, 0xFF, 0xFD, 0xC0, 0x00, 0x00, 0x0D,
			0x7F, 0xFF, 0xFF, 0xB8, 0x00, 0x00, 0x01, 0xD3,
			0xFF, 0xFF, 0xF9, 0x42, 0xD0, 0x00, 0x16, 0x5E,
			0x3F, 0xFF, 0x94, 0x87, 0x00, 0x00, 0xD5, 0x2F,
			0xFF, 0xFD, 0xD0, 0xE0, 0x00, 0x08, 0xDE, 0x55,
			0x60, 0x00, 0x86, 0x55, 0x00, 0x21, 0xE5, 0x55,
			0xFF, 0xFF, 0xF5, 0x4F, 0xFF, 0xF4, 0xEA, 0xC0,
			0x00, 0x00, 0x00, 0x49, 0x80, 0x01, 0x54, 0xD9,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED, 0xA0,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61		},
	},
	{ .name = "sm2",
	  .nid = 0,
	  .curve = TPM_ECC_SM2_P256,
	  /* p */
	  .C[0].s = 32,
	  .C[0].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
	  /* a */
	  .C[1].s = 32,
	  .C[1].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
		},
	  /* b */
	  .C[2].s = 32,
	  .C[2].b = (BYTE [])
		{
			0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
			0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
			0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
			0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
		},
	  /* gX */
	  .C[3].s = 32,
	  .C[3].b = (BYTE [])
		{
			0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
			0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
			0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
			0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
		},
	  /* gY */
	  .C[4].s = 32,
	  .C[4].b = (BYTE [])
		{
			0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
			0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
			0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
			0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
		},
	  /* order */
	  .C[5].s = 32,
	  .C[5].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
			0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23,
		},
	},
	{ .name = NULL, }
};

int tpm2_rsa_decrypt(const struct app_data *ad, PUBLIC_KEY_RSA_2B *cipherText,
		     unsigned char *to, int padding, int protection,
		     char *srk_auth)
{
	TPM_RC rc;
	int rv;
	TSS_CONTEXT *tssContext;
	TPM_HANDLE keyHandle;
	TPMT_RSA_DECRYPT inScheme;
	PUBLIC_KEY_RSA_2B message;
	TPM_HANDLE authHandle;
	TPM_SE sessionType;

	keyHandle = tpm2_load_key(&tssContext, ad, srk_auth, NULL);

	if (keyHandle == 0) {
		fprintf(stderr, "Failed to get Key Handle in TPM RSA key routines\n");

		return -1;
	}

	rv = -1;
	if (padding == RSA_PKCS1_PADDING) {
		inScheme.scheme = TPM_ALG_RSAES;
	} else if (padding == RSA_NO_PADDING) {
		inScheme.scheme = TPM_ALG_NULL;
	} else if (padding == RSA_PKCS1_OAEP_PADDING) {
		inScheme.scheme = TPM_ALG_OAEP;
		/* for openssl RSA, the padding is hard coded */
		inScheme.details.oaep.hashAlg = TPM_ALG_SHA1;
	} else {
		fprintf(stderr, "Can't process padding type: %d\n", padding);
		goto out;
	}

	sessionType = ad->req_policy_session ? TPM_SE_POLICY : TPM_SE_HMAC;

	rc = tpm2_get_session_handle(tssContext, &authHandle, 0, sessionType,
				     ad->Public.publicArea.nameAlg);
	if (rc)
		goto out;

	if (sessionType == TPM_SE_POLICY) {
		rc = tpm2_init_session(tssContext, authHandle,
				       ad, ad->Public.publicArea.nameAlg);
		if (rc)
			goto out;
	}

	rc = tpm2_RSA_Decrypt(tssContext, keyHandle, cipherText, &inScheme,
			      &message, authHandle, ad->auth, protection);

	if (rc) {
		tpm2_error(rc, "TPM2_RSA_Decrypt");
		/* failure means auth handle is not flushed */
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}

	memcpy(to, message.buffer, message.size);

	rv = message.size;
 out:
	tpm2_unload_key(tssContext, keyHandle);
	return rv;
}

ECDSA_SIG *tpm2_sign_ecc(const struct app_data *ad, const unsigned char *dgst,
			 int dgst_len, char *srk_auth)
{
	TPM_RC rc;
	TPM_HANDLE keyHandle;
	DIGEST_2B digest;
	TPMT_SIG_SCHEME inScheme;
	TPMT_SIGNATURE signature;
	TSS_CONTEXT *tssContext;
	TPM_HANDLE authHandle;
	TPM_SE sessionType;
	ECDSA_SIG *sig;
	BIGNUM *r, *s;
	int len = tpm2_curve_to_order(ad->Public.publicArea.parameters.eccDetail.curveID);

	/* so we give it a digest equal to the key length, except if that
	 * goes over the max known digest size, in which case we give it that */
	if (len > SHA512_DIGEST_LENGTH)
		len = SHA512_DIGEST_LENGTH;
	switch (len) {
	case SHA_DIGEST_LENGTH:
		inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA1;
		break;
	case SHA256_DIGEST_LENGTH:
		inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
		break;
	case SHA384_DIGEST_LENGTH:
		inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA384;
		break;
#ifdef TPM_ALG_SHA512
	case SHA512_DIGEST_LENGTH:
		inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA512;
		break;
#endif
	default:
		fprintf(stderr, "ECDSA signature: Unknown digest length, cannot deduce hash type for TPM\n");
		return NULL;
	}

	keyHandle = tpm2_load_key(&tssContext, ad, srk_auth, NULL);
	if (keyHandle == 0)
		return NULL;

	inScheme.scheme = TPM_ALG_ECDSA;
	digest.size = len;
	if (len < dgst_len) {
		memcpy(digest.buffer, dgst, len);
	} else {
		memset(digest.buffer, 0, len);
		memcpy(digest.buffer + len - dgst_len, dgst, dgst_len);
	}

	sessionType = ad->req_policy_session ? TPM_SE_POLICY : TPM_SE_HMAC;

	sig = NULL;
	rc = tpm2_get_session_handle(tssContext, &authHandle, 0, sessionType,
				     ad->Public.publicArea.nameAlg);
	if (rc)
		goto out;

	if (sessionType == TPM_SE_POLICY) {
		rc = tpm2_init_session(tssContext, authHandle,
				       ad, ad->Public.publicArea.nameAlg);
		if (rc)
			goto out;
	}

	rc = tpm2_Sign(tssContext, keyHandle, &digest, &inScheme, &signature,
		       authHandle, ad->auth);
	if (rc) {
		tpm2_error(rc, "TPM2_Sign");
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}

	sig = ECDSA_SIG_new();
	if (!sig)
		goto out;

	r = BN_bin2bn(VAL_2B(signature.signature.ecdsa.signatureR, buffer),
		      VAL_2B(signature.signature.ecdsa.signatureR, size),
		      NULL);
	s = BN_bin2bn(VAL_2B(signature.signature.ecdsa.signatureS, buffer),
		      VAL_2B(signature.signature.ecdsa.signatureS, size),
		      NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	sig->r = r;
	sig->s = s;
#else
	ECDSA_SIG_set0(sig, r, s);
#endif
 out:
	tpm2_unload_key(tssContext, keyHandle);
	return sig;
}

int tpm2_ecdh_x(struct app_data *ad, unsigned char **psec, size_t *pseclen,
		const TPM2B_ECC_POINT *inPoint, const char *srk_auth)
{
	TPM_RC rc;
	TPM_HANDLE keyHandle;
	TPM2B_ECC_POINT outPoint;
	TSS_CONTEXT *tssContext;
	TPM_HANDLE authHandle;
	TPM_SE sessionType;
	size_t len;
	int ret;

	keyHandle = tpm2_load_key(&tssContext, ad, srk_auth, NULL);
	if (keyHandle == 0) {
		fprintf(stderr, "Failed to get Key Handle in TPM EC key routines\n");
		return 0;
	}

	ret = 0;
	len = tpm2_curve_to_order(ad->Public.publicArea.parameters.eccDetail.curveID);
	sessionType = ad->req_policy_session ? TPM_SE_POLICY : TPM_SE_HMAC;

	rc = tpm2_get_session_handle(tssContext, &authHandle, 0, sessionType,
				     ad->Public.publicArea.nameAlg);
	if (rc)
		goto out;

	if (sessionType == TPM_SE_POLICY) {
		rc = tpm2_init_session(tssContext, authHandle,
				       ad, ad->Public.publicArea.nameAlg);
		if (rc)
			goto out;
	}

	rc = tpm2_ECDH_ZGen(tssContext, keyHandle, inPoint, &outPoint,
			    authHandle, ad->auth);
	if (rc) {
		tpm2_error(rc, "TPM2_ECDH_ZGen");
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}

	if (!*psec) {
		*psec = OPENSSL_malloc(len);
		if (!*psec)
			goto out;
	}
	*pseclen = len;
	memset(*psec, 0, len);

	/* zero pad the X point */
	memcpy(*psec + len - VAL_2B(outPoint.point.x, size),
	       VAL_2B(outPoint.point.x, buffer),
	       VAL_2B(outPoint.point.x, size));
	ret = 1;
 out:
	tpm2_unload_key(tssContext, keyHandle);
	return ret;
}

TPM_RC tpm2_ObjectPublic_GetName(NAME_2B *name,
				 TPMT_PUBLIC *tpmtPublic)
{
	TPM_RC rc = 0;
	uint16_t written = 0;
	TPMT_HA digest;
	uint32_t sizeInBytes;
	uint8_t buffer[MAX_RESPONSE_SIZE];

	/* marshal the TPMT_PUBLIC */
	if (rc == 0) {
		INT32 size = MAX_RESPONSE_SIZE;
		uint8_t *buffer1 = buffer;
		rc = TSS_TPMT_PUBLIC_Marshal(tpmtPublic, &written, &buffer1, &size);
	}
	/* hash the public area */
	if (rc == 0) {
		sizeInBytes = TSS_GetDigestSize(tpmtPublic->nameAlg);
		digest.hashAlg = tpmtPublic->nameAlg;	/* Name digest algorithm */
		/* generate the TPMT_HA */
		rc = TSS_Hash_Generate(&digest,
				       written, buffer,
				       0, NULL);
	}
	if (rc == 0) {
		/* copy the digest */
		memcpy(name->name + sizeof(TPMI_ALG_HASH), (uint8_t *)&digest.digest, sizeInBytes);
		/* copy the hash algorithm */
		TPMI_ALG_HASH nameAlgNbo = htons(tpmtPublic->nameAlg);
		memcpy(name->name, (uint8_t *)&nameAlgNbo, sizeof(TPMI_ALG_HASH));
		/* set the size */
		name->size = sizeInBytes + sizeof(TPMI_ALG_HASH);
	}
	return rc;
}

TPM_RC tpm2_load_srk(TSS_CONTEXT *tssContext, TPM_HANDLE *h, const char *auth,
		     TPM2B_PUBLIC *pub, TPM_HANDLE hierarchy,
		     enum tpm2_type type)
{
	TPM_RC rc;
	TPM2B_SENSITIVE_CREATE inSensitive;
	TPM2B_PUBLIC inPublic;
	TPM_HANDLE session;

	if (auth) {
		VAL_2B(inSensitive.sensitive.userAuth, size) = strlen(auth);
		memcpy(VAL_2B(inSensitive.sensitive.userAuth, buffer), auth, strlen(auth));
	} else {
		VAL_2B(inSensitive.sensitive.userAuth, size) = 0;
	}

	/* no sensitive date for storage keys */
	VAL_2B(inSensitive.sensitive.data, size) = 0;

	/* public parameters for an RSA2048 key  */
	inPublic.publicArea.type = TPM_ALG_ECC;
	inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	VAL(inPublic.publicArea.objectAttributes) =
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_RESTRICTED;
	if (type != TPM2_LEGACY)
		VAL(inPublic.publicArea.objectAttributes) |=
			TPMA_OBJECT_FIXEDPARENT |
			TPMA_OBJECT_FIXEDTPM;

	inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

	VAL_2B(inPublic.publicArea.unique.ecc.x, size) = 0;
	VAL_2B(inPublic.publicArea.unique.ecc.y, size) = 0;
	VAL_2B(inPublic.publicArea.authPolicy, size) = 0;

	/* use a bound session here because we have no known key objects
	 * to encrypt a salt to */
	rc = tpm2_get_bound_handle(tssContext, &session, hierarchy, auth);
	if (rc)
		return rc;

	rc = tpm2_CreatePrimary(tssContext, hierarchy, &inSensitive, &inPublic,
				h, pub, session, auth);

	if (rc) {
		tpm2_error(rc, "TSS_CreatePrimary");
		tpm2_flush_handle(tssContext, session);
	}

	return rc;
}

void tpm2_flush_srk(TSS_CONTEXT *tssContext, TPM_HANDLE hSRK)
{
	/* only flush if it's a volatile key which we must have created */
	if (tpm2_handle_mso(tssContext, hSRK, TPM_HT_TRANSIENT))
		tpm2_flush_handle(tssContext, hSRK);
}

void tpm2_flush_handle(TSS_CONTEXT *tssContext, TPM_HANDLE h)
{
	if (!h)
		return;

	tpm2_FlushContext(tssContext, h);
}

int tpm2_get_ecc_group(EC_KEY *eck, TPMI_ECC_CURVE curveID)
{
	const int nid = tpm2_curve_name_to_nid(curveID);
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b, *gX, *gY, *n, *h;
	TPMS_ALGORITHM_DETAIL_ECC parameters;
	TSS_CONTEXT *tssContext = NULL;
	TPM_RC rc;
	EC_GROUP *g = NULL;
	EC_POINT *P = NULL;
	int ret = 0;

	if (nid) {
		g = EC_GROUP_new_by_curve_name(nid);
		EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
		goto out;
	}

	/* openssl doesn't have a nid for the curve, so need
	 * to set the exact parameters in the key */
	rc = TSS_Create(&tssContext);
	if (rc) {
		tpm2_error(rc, "TSS_Create");
		goto err;
	}
	rc = tpm2_ECC_Parameters(tssContext, curveID, &parameters);

	TSS_Delete(tssContext);

	if (rc) {
		tpm2_error(rc, "TPM2_ECC_Parameters");
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx)
		goto err;

	BN_CTX_start(ctx);
	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	gX = BN_CTX_get(ctx);
	gY = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);

	if (!p || !a || !b || !gX || !gY || !n || !h)
		goto err;

	BN_bin2bn(VAL_2B(parameters.p, buffer), VAL_2B(parameters.p, size), p);
	BN_bin2bn(VAL_2B(parameters.a, buffer), VAL_2B(parameters.a, size), a);
	BN_bin2bn(VAL_2B(parameters.b, buffer), VAL_2B(parameters.a, size), b);
	BN_bin2bn(VAL_2B(parameters.gX, buffer), VAL_2B(parameters.gX, size), gX);
	BN_bin2bn(VAL_2B(parameters.gY, buffer), VAL_2B(parameters.gY, size), gY);
	BN_bin2bn(VAL_2B(parameters.n, buffer), VAL_2B(parameters.n, size), n);
	BN_bin2bn(VAL_2B(parameters.h, buffer), VAL_2B(parameters.h, size), h);

	g = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	if (!g)
		goto err;

	EC_GROUP_set_asn1_flag(g, 0);
	P = EC_POINT_new(g);
	if (!P)
		goto err;
	if (!EC_POINT_set_affine_coordinates_GFp(g, P, gX, gY, ctx))
		goto err;
	if (!EC_GROUP_set_generator(g, P, n, h))
		goto err;
 out:
	ret = 1;
	EC_KEY_set_group(eck, g);

 err:
	if (P)
		EC_POINT_free(P);
	if (g)
		EC_GROUP_free(g);
	if (ctx) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return ret;
}

static EVP_PKEY *tpm2_to_openssl_public_ecc(TPMT_PUBLIC *pub)
{
	EC_KEY *eck = EC_KEY_new();
	EVP_PKEY *pkey;
	BIGNUM *x, *y;

	if (!eck)
		return NULL;
	pkey = EVP_PKEY_new();
	if (!pkey)
		goto err_free_eck;
	if (!tpm2_get_ecc_group(eck, pub->parameters.eccDetail.curveID))
		goto err_free_pkey;
	x = BN_bin2bn(VAL_2B(pub->unique.ecc.x, buffer),
		      VAL_2B(pub->unique.ecc.x, size), NULL);
	y = BN_bin2bn(VAL_2B(pub->unique.ecc.y, buffer),
		      VAL_2B(pub->unique.ecc.y, size), NULL);
	EC_KEY_set_public_key_affine_coordinates(eck, x, y);
	BN_free(y);
	BN_free(x);
	if (!EVP_PKEY_assign_EC_KEY(pkey, eck))
		goto err_free_pkey;

	return pkey;

 err_free_pkey:
	EVP_PKEY_free(pkey);
 err_free_eck:
	EC_KEY_free(eck);

	return NULL;
}

static EVP_PKEY *tpm2_to_openssl_public_rsa(TPMT_PUBLIC *pub)
{
	RSA *rsa = RSA_new();
	EVP_PKEY *pkey;
	unsigned long exp;
	BIGNUM *n, *e;

	if (!rsa)
		return NULL;
	pkey = EVP_PKEY_new();
	if (!pkey)
		goto err_free_rsa;
	e = BN_new();
	if (!e)
		goto err_free_pkey;
	n = BN_new();
	if (!n)
		goto err_free_e;
	if (pub->parameters.rsaDetail.exponent == 0)
		exp = 0x10001;
	else
		exp = pub->parameters.rsaDetail.exponent;
	if (!BN_set_word(e, exp))
		goto err_free;
	if (!BN_bin2bn(VAL_2B(pub->unique.rsa, buffer),
		       VAL_2B(pub->unique.rsa, size), n))
		goto err_free;
#if OPENSSL_VERSION_NUMBER < 0x10100000
	rsa->n = n;
	rsa->e = e;
#else
	RSA_set0_key(rsa, n, e, NULL);
#endif
	if (!EVP_PKEY_assign_RSA(pkey, rsa))
		goto err_free;

	return pkey;

 err_free:
	BN_free(n);
 err_free_e:
	BN_free(e);
 err_free_pkey:
	EVP_PKEY_free(pkey);
 err_free_rsa:
	RSA_free(rsa);

	return NULL;
}

EVP_PKEY *tpm2_to_openssl_public(TPMT_PUBLIC *pub)
{
	switch (pub->type) {
	case TPM_ALG_RSA:
		return tpm2_to_openssl_public_rsa(pub);
	case TPM_ALG_ECC:
		return tpm2_to_openssl_public_ecc(pub);
	default:
		break;
	}
	return NULL;
}

TPM_RC tpm2_readpublic(TSS_CONTEXT *tssContext, TPM_HANDLE handle,
		       TPMT_PUBLIC *pub)
{
	return tpm2_ReadPublic(tssContext, handle, pub, TPM_RH_NULL);
}

TPM_RC tpm2_get_bound_handle(TSS_CONTEXT *tssContext, TPM_HANDLE *handle,
			     TPM_HANDLE bind, const char *auth)
{
	TPM_RC rc;
	TPMT_SYM_DEF symmetric;

	symmetric.algorithm = TPM_ALG_AES;
	symmetric.keyBits.aes = 128;
	symmetric.mode.aes = TPM_ALG_CFB;

	rc = tpm2_StartAuthSession(tssContext, TPM_RH_NULL, bind,
				   TPM_SE_HMAC, &symmetric,
				   TPM_ALG_SHA256, handle, auth);
	if (rc)
		tpm2_error(rc, "TPM2_StartAuthSession");


	return rc;
}

TPM_RC tpm2_get_session_handle(TSS_CONTEXT *tssContext, TPM_HANDLE *handle,
			       TPM_HANDLE salt_key, TPM_SE sessionType,
			       TPM_ALG_ID name_alg)
{
	TPM_RC rc;
	TPMT_SYM_DEF symmetric;

	/* 0 means no key, which we express as TPM_RH_NULL to the TSS */
	if (!salt_key)
		salt_key = TPM_RH_NULL;

	symmetric.algorithm = TPM_ALG_AES;
	symmetric.keyBits.aes = 128;
	symmetric.mode.aes = TPM_ALG_CFB;

	rc = tpm2_StartAuthSession(tssContext, salt_key, TPM_RH_NULL,
				   sessionType, &symmetric, name_alg,
				   handle, NULL);

	if (rc)
		tpm2_error(rc, "TPM2_StartAuthSession");

	return rc;
}

static TPM_RC tpm2_try_policy(TSS_CONTEXT *tssContext, TPM_HANDLE handle,
			      int num_commands, struct policy_command *commands,
			      TPM_ALG_ID name_alg, const char *prefix)
{
	INT32 size;
	BYTE *policy;
	TPM_RC rc = TPM_RC_SUCCESS, reason_rc = 0;
	int i;
	char reason[256];
	int name_alg_size = TSS_GetDigestSize(name_alg);

	reason[0] = '\0';

	for (i = 0; i < num_commands; i++) {
		size = commands[i].size;
		policy = commands[i].policy;

		switch (commands[i].code) {
		case TPM_CC_PolicyPCR: {
			DIGEST_2B pcrDigest;
			TPML_PCR_SELECTION pcrs;

			rc = TPML_PCR_SELECTION_Unmarshal(
				&pcrs, &policy, &size);
			if (rc)
				goto unmarshal_failure;
			pcrDigest.size = name_alg_size;
			memcpy(pcrDigest.buffer,
			       policy, name_alg_size);
			sprintf(reason, "PCR Mismatch");
			reason_rc = TPM_RC_VALUE;

			rc = tpm2_PolicyPCR(tssContext, handle,
					    &pcrDigest, &pcrs);

			break;
		}
		case TPM_CC_PolicyAuthValue:
			rc = tpm2_PolicyAuthValue(tssContext, handle);
			break;
		case TPM_CC_PolicyCounterTimer: {
			DIGEST_2B operandB;
			UINT16 offset;
			TPM_EO operation;
			BYTE *p_buffer;
			INT32 p_size;
			int i, c;
			const char *const operand[] = {
				[TPM_EO_EQ] = "==",
				[TPM_EO_NEQ] = "!=",
				[TPM_EO_SIGNED_GT] = ">(s)",
				[TPM_EO_UNSIGNED_GT] = ">",
				[TPM_EO_SIGNED_LT] = "<(s)",
				[TPM_EO_UNSIGNED_LT] = "<",
				[TPM_EO_SIGNED_GE] = ">=(s)",
				[TPM_EO_UNSIGNED_GE] = ">=",
				[TPM_EO_SIGNED_LE] = "<=(s)",
				[TPM_EO_UNSIGNED_LE] = "<=",
				[TPM_EO_BITSET] = "bitset",
				[TPM_EO_BITCLEAR] = "bitclear",
			};

			/* last UINT16 is the operand */
			p_buffer = policy + size - 2;
			p_size = 2;
			TPM_EO_Unmarshal(&operation, &p_buffer, &p_size);
			/* second to last UINT16 is the offset */
			p_buffer = policy + size - 4;
			p_size = 2;
			UINT16_Unmarshal(&offset, &p_buffer, &p_size);

			/* and the rest is the OperandB */
			operandB.size = size - 4;
			memcpy(operandB.buffer, policy, size - 4);

			c = sprintf(reason,
				    "Counter Timer at offset %d is not %s ",
				    offset, operand[operation]);
			for (i = 0; i < size - 4; i++)
				c += sprintf(&reason[c], "%02x", policy[i]);

			reason[c] = '\0';
			reason_rc = TPM_RC_POLICY;

			rc = tpm2_PolicyCounterTimer(tssContext, handle,
						     &operandB, offset,
						     operation);

			break;
		}
		case TPM_CC_PolicyAuthorize: {
			TPM2B_PUBLIC pub;
			DIGEST_2B nonce;
			TPMT_SIGNATURE sig;
			DIGEST_2B policyHash;
			TPMT_HA sigHash;
			DIGEST_2B sigDigest;
			TPM_HANDLE sigkey;
			TPMT_TK_VERIFIED ticket;
			NAME_2B name;

			rc = TPM2B_PUBLIC_Unmarshal(&pub, &policy, &size, FALSE);
			if (rc)
				goto unmarshal_failure;

			rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&nonce, &policy, &size);
			if (rc)
				goto unmarshal_failure;
			rc = TPMT_SIGNATURE_Unmarshal(&sig, &policy, &size, FALSE);
			if (rc)
				goto unmarshal_failure;
			rc = tpm2_PolicyGetDigest(tssContext, handle, &policyHash);
			if (rc) {
				sprintf(reason, "PolicyGetDigest");
				break;
			}
			sigHash.hashAlg = name_alg;
			TSS_Hash_Generate(&sigHash,
					  policyHash.size, policyHash.buffer,
					  nonce.size, nonce.buffer,
					  0, NULL);
			sigDigest.size = TSS_GetDigestSize(name_alg);
			memcpy(sigDigest.buffer, &sigHash.digest, sigDigest.size);
			rc = tpm2_LoadExternal(tssContext, NULL, &pub, TPM_RH_OWNER, &sigkey, &name);
			if (rc) {
				sprintf(reason, "LoadExternal");
				break;
			}
			rc = tpm2_VerifySignature(tssContext, sigkey, &sigDigest, &sig, &ticket);
			tpm2_flush_handle(tssContext, sigkey);
			if (rc) {
				sprintf(reason, "Signature Failed");
				break;
			}

			rc = tpm2_PolicyAuthorize(tssContext, handle, &policyHash, &nonce, &name, &ticket);
			if (rc)
				sprintf(reason, "PolicyAuthorize failed");

			break;
		}
		case TPM_CC_PolicyLocality:
			rc = tpm2_PolicyLocality(tssContext, handle, policy[0]);
			if (rc)
				sprintf(reason, "Locality Check 0x%x failed",
					policy[0]);
			break;

		default:
			fprintf(stderr, "%sUnsupported policy command %d\n",
				prefix, commands[i].code);
			return TPM_RC_FAILURE;
		}

		if (rc) {
			TPM_RC check_rc;

			/* strip additional parameter or session information */
			if ((rc & 0x180) == RC_VER1)
				check_rc = rc & 0x1ff;
			else if (rc & RC_FMT1)
				check_rc = rc & 0xbf;
			else
				check_rc = rc;

			if (check_rc == reason_rc && reason[0]) {
				fprintf(stderr, "%sPolicy Failure: %s\n",
					prefix, reason);
			} else {
				if (!reason[0])
					sprintf(reason, "%spolicy command", prefix);
				tpm2_error(rc, reason);
			}
			return rc;
		}
	}
	return rc;

 unmarshal_failure:
	sprintf(reason, "%sunmarshal", prefix);
	tpm2_error(rc, reason);
	return rc;
}

TPM_RC tpm2_init_session(TSS_CONTEXT *tssContext, TPM_HANDLE handle,
			 const struct app_data *app_data, TPM_ALG_ID name_alg)
{
	int num_commands;
	struct policy_command *commands;
	char prefix[128];
	TPM_RC rc;

	if (app_data->pols == NULL)
		return TPM_RC_SUCCESS;

	commands = app_data->pols[0].commands;
	num_commands = app_data->pols[0].num_commands;

	if (app_data->num_pols > 1 &&
	    commands[0].code == TPM_CC_PolicyAuthorize) {
		int i;

		commands++;
		num_commands--;
		for (i = 1; i < app_data->num_pols; i++) {
			struct policies *pols = &app_data->pols[i];

			if (pols->name)
				sprintf(prefix, "Signed Policy %d (%s) ", i,
					pols->name);
			else
				sprintf(prefix, "Signed policy %d ", i);

			rc = tpm2_PolicyRestart(tssContext, handle);
			if (rc != TPM_RC_SUCCESS)
				break;
			rc = tpm2_try_policy(tssContext, handle,
					     pols->num_commands,
					     pols->commands,
					     name_alg, prefix);
			if (rc == TPM_RC_SUCCESS)
				break;
		}
		if (rc != TPM_RC_SUCCESS)
			goto out;

		fprintf(stderr, "%ssucceeded\n", prefix);
	}

	rc = tpm2_try_policy(tssContext, handle, num_commands, commands,
			     name_alg, "");
 out:
	if (rc != TPM_RC_SUCCESS)
		tpm2_flush_handle(tssContext, handle);

	return rc;
}

TPMI_ECC_CURVE tpm2_curve_name_to_TPMI(const char *name)
{
	int i;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (strcmp(name, tpm2_supported_curves[i].name) == 0)
			return tpm2_supported_curves[i].curve;

	return TPM_ECC_NONE;
}

int tpm2_curve_name_to_nid(TPMI_ECC_CURVE curve)
{
	int i;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (tpm2_supported_curves[i].curve == curve)
			return tpm2_supported_curves[i].nid;

	return 0;
}

int tpm2_curve_to_order(TPMI_ECC_CURVE curve)
{
	int i;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (tpm2_supported_curves[i].curve == curve)
			return tpm2_supported_curves[i].C[5].s;

	return 0;
}

TPMI_ECC_CURVE tpm2_nid_to_curve_name(int nid)
{
	int i;

	if (!nid)
		return TPM_ECC_NONE;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (tpm2_supported_curves[i].nid == nid)
			return tpm2_supported_curves[i].curve;

	return TPM_ECC_NONE;
}

TPMI_ECC_CURVE tpm2_get_curve_name(const EC_GROUP *g)
{
	int nid = EC_GROUP_get_curve_name(g);
	const EC_POINT *P;
	BIGNUM *C[6], *N, *R;
	BN_CTX *ctx;
	int i;
	TPMI_ECC_CURVE curve = TPM_ECC_NONE;

	if (nid)
		return tpm2_nid_to_curve_name(nid);

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	for (i = 0; i < 6; i++)
		C[i] = BN_CTX_get(ctx);
	N = BN_CTX_get(ctx);
	R = BN_CTX_get(ctx);

	EC_GROUP_get_curve_GFp(g, C[0], C[1], C[2], ctx);
	P = EC_GROUP_get0_generator(g);
	EC_POINT_get_affine_coordinates_GFp(g, P, C[3], C[4], ctx);
	EC_GROUP_get_order(g, C[5], ctx);

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++) {
		int j;
		for (j = 0; j < 6; j++) {
			BN_bin2bn(tpm2_supported_curves[i].C[j].b,
				  tpm2_supported_curves[i].C[j].s, N);
			BN_sub(R, N, C[j]);
			if (!BN_is_zero(R))
				break;
		}
		if (j == 6) {
			curve = tpm2_supported_curves[i].curve;
			break;
		}
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return curve;
}

const char *tpm2_curve_name_to_text(TPMI_ECC_CURVE curve)
{
	int i;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (tpm2_supported_curves[i].curve == curve)
			return tpm2_supported_curves[i].name;

	return NULL;
}

const char *tpm2_set_unique_tssdir(void)
{
	char *dir_owner = getenv("XDG_RUNTIME_DIR_OWNER");
	char *dir_group = getenv("XDG_RUNTIME_DIR_GROUP");
	char *prefix = getenv("XDG_RUNTIME_DIR"), *template,
		*dir;
	int ret, len = 0;
	struct stat st;
	struct passwd *pwd;
	struct group *grp;
	uid_t uid;
	gid_t gid;

	if (!prefix)
		prefix = "/tmp";

	len = snprintf(NULL, 0, "%s/tss2.XXXXXX", prefix);
	if (len <= 0)
		return NULL;
	template = OPENSSL_malloc(len + 1);
	if (!template)
		return NULL;

	len++;
	len = snprintf(template, len, "%s/tss2.XXXXXX", prefix);

	dir = mkdtemp(template);
	if (!dir)
		goto out;

	if (stat(dir, &st) == -1)
		goto out;

	uid = st.st_uid;
	if (dir_owner) {
		pwd = getpwnam(dir_owner);
		if (pwd)
			uid = pwd->pw_uid;
	}

	gid = st.st_gid;
	if (dir_group) {
		grp = getgrnam(dir_group);
		if (grp)
			gid = grp->gr_gid;
	}

	if (geteuid() != 0 && (uid != getuid() || gid != getgid()))
		goto out;

	if (dir_owner || dir_group) {
		ret = chown(dir, uid, gid);
		if (ret == -1) {
			fprintf(stderr, "chown() failed (%s)", strerror(errno));
			unlink(dir);
			dir = NULL;
		}
	}
out:
	return dir;
}

void tpm2_rm_keyfile(const char *dir, TPM_HANDLE key)
{
	char keyfile[1024];

	snprintf(keyfile, sizeof(keyfile), "%s/h%08x.bin", dir, key);
	unlink(keyfile);
	snprintf(keyfile, sizeof(keyfile), "%s/hp%08x.bin", dir, key);
	unlink(keyfile);
}

void tpm2_rm_tssdir(const char *dir)
{
	if (rmdir(dir) < 0) {
		fprintf(stderr, "Unlinking %s", dir);
		perror(":");
	}
}

TPM_RC tpm2_create(TSS_CONTEXT **tsscp, const char *dir)
{
	TPM_RC rc;

	rc = TSS_Create(tsscp);
	if (rc) {
		tpm2_error(rc, "TSS_Create");
		return rc;
	}

#ifdef HAVE_IBM_TSS
	if (dir) {
		rc = TSS_SetProperty(*tsscp, TPM_DATA_DIR, dir);
		if (rc) {
			tpm2_error(rc, "TSS_SetProperty");
			return rc;
		}
	}
#endif

	return TPM_RC_SUCCESS;
}

int tpm2_get_public_point(TPM2B_ECC_POINT *tpmpt, const EC_GROUP *group,
			  const EC_POINT *pt)
{
	BN_CTX *ctx;
	size_t len;
	unsigned char point[MAX_ECC_KEY_BYTES*2 + 1];

	ctx = BN_CTX_new();
	if (!ctx)
		return 0;
	BN_CTX_start(ctx);
	len = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
				 point, sizeof(point), ctx);
	BN_CTX_free(ctx);

	len--;
	len >>= 1;

	memcpy(VAL_2B(tpmpt->point.x, buffer), point + 1, len);
	VAL_2B(tpmpt->point.x, size) = len;
	memcpy(VAL_2B(tpmpt->point.y, buffer), point + 1 + len, len);
	VAL_2B(tpmpt->point.y, size) = len;

	return len;
}

static char *tpm2_get_auth_ui(UI_METHOD *ui_method, char *prompt, void *cb_data)
{
	UI *ui = UI_new();
	/* Max auth size is name algorithm hash length, so this
	 * is way bigger than necessary */
	char auth[256], *ret = NULL;
	int len;

	if (ui_method)
		UI_set_method(ui, ui_method);

	UI_add_user_data(ui, cb_data);

	if (UI_add_input_string(ui, prompt, UI_INPUT_FLAG_DEFAULT_PWD,
				auth, 0, sizeof(auth)) == 0) {
		fprintf(stderr, "UI_add_input_string failed\n");
		goto out;
	}

	if (UI_process(ui)) {
		fprintf(stderr, "UI_process failed\n");
		goto out;
	}

	len = strlen(auth);
	ret = OPENSSL_malloc(len + 1);
	if (!ret)
		goto out;

	strcpy(ret, auth);

 out:
	UI_free(ui);

	return ret;
}

static char *tpm2_get_auth_pem(char *input_string, void *cb_data)
{
	char auth[256], *ret;
	int len;

	EVP_set_pw_prompt(input_string);

	PEM_def_callback(auth, sizeof(auth), 0, cb_data);
	EVP_set_pw_prompt(NULL);

	len = strlen(auth);
	ret = OPENSSL_malloc(len + 1);
	if (!ret)
		goto out;

	strcpy(ret, auth);

 out:
	return ret;
}

char *tpm2_get_auth(UI_METHOD *ui, char *input_string, void *cb_data)
{
	if (ui)
		return tpm2_get_auth_ui(ui, input_string, cb_data);
	else
		return tpm2_get_auth_pem(input_string, cb_data);
}

static int tpm2_engine_load_key_policy(struct app_data *app_data,
				       STACK_OF(TSSOPTPOLICY) *st_policy,
				       STACK_OF(TSSAUTHPOLICY) *auth_policy)
{
	struct policy_command *command;
	TSSOPTPOLICY *policy;
	int i, len;
	int num_policies = 1, num_commands;

	num_commands = sk_TSSOPTPOLICY_num(st_policy);
	if (num_commands <= 0)
		return 1;

	policy = sk_TSSOPTPOLICY_value(st_policy, 0);
	if (ASN1_INTEGER_get(policy->CommandCode) == TPM_CC_PolicyAuthorize
	    && auth_policy == NULL) {
		fprintf(stderr, "Key unusable (no signed policies)\n");
		return 0;
	}

	if (auth_policy)
		num_policies += sk_TSSAUTHPOLICY_num(auth_policy);

	app_data->num_pols = num_policies;

	len = sizeof(*app_data->pols) * num_policies;
	app_data->pols = OPENSSL_malloc(len);
	if (!app_data->pols)
		return 0;

	len = sizeof(struct policy_command) * num_commands;
	app_data->pols[0].num_commands = num_commands;
	app_data->pols[0].commands = OPENSSL_malloc(len);
	app_data->pols[0].name = NULL;
	if (!app_data->pols[0].commands)
		return 0;

	for (i = 0; i < num_commands; i++) {
		policy = sk_TSSOPTPOLICY_value(st_policy, i);
		if (!policy)
			return 0;

		command = app_data->pols[0].commands + i;
		command->code = ASN1_INTEGER_get(policy->CommandCode);
		command->size = policy->CommandPolicy->length;
		command->policy = NULL;

		if (!command->size)
			continue;

		command->policy = OPENSSL_malloc(command->size);
		if (!command->policy)
			return 0;

		memcpy(command->policy, policy->CommandPolicy->data,
		       command->size);
	}

	if (num_policies == 1)
		return 1;

	for (i = 1; i < num_policies; i++) {
		int j;
		TSSAUTHPOLICY *ap = sk_TSSAUTHPOLICY_value(auth_policy, i-1);
		struct policies *pols = &app_data->pols[i];
		if (!ap)
			return 0;

		if (ap->name) {
			pols->name = OPENSSL_malloc(ap->name->length + 1);
			if (!pols->name)
				return 0;
			memcpy(pols->name, ap->name->data, ap->name->length);
			pols->name[ap->name->length] = '\0';
		} else {
			pols->name = NULL;
		}

		num_commands = sk_TSSOPTPOLICY_num(ap->policy);
		len = sizeof(struct policy_command) * num_commands;
		app_data->pols[i].num_commands = num_commands;
		app_data->pols[i].commands = OPENSSL_malloc(len);
		if (!app_data->pols[i].commands)
			return 0;

		for (j = 0; j < num_commands; j++) {
			policy = sk_TSSOPTPOLICY_value(ap->policy, j);

			command = app_data->pols[i].commands + j;
			command->code = ASN1_INTEGER_get(policy->CommandCode);
			command->size = policy->CommandPolicy->length;
			command->policy = NULL;

			if (!command->size)
				continue;

			command->policy = OPENSSL_malloc(command->size);
			if (!command->policy)
				return 0;

			memcpy(command->policy, policy->CommandPolicy->data,
			       command->size);
		}
	}
	return 1;
}

static const EVP_MD *tpm2_md(TPM_ALG_ID alg)
{
	switch (alg) {
	case TPM_ALG_SHA1:
		return EVP_sha1();

	case TPM_ALG_SHA256:
		return EVP_sha256();

	case TPM_ALG_SHA384:
		return EVP_sha384();

#ifdef TPM_ALG_SHA512
	case TPM_ALG_SHA512:
		return EVP_sha512();
#endif
#ifdef TPM_ALG_SM3_256
	case TPM_ALG_SM3_256:
		return EVP_sm3();
#endif
	default:
		fprintf(stderr, "Unknown TPM hash algorithm 0x%x\n", alg);
		exit(1);
	}
}

TPM_RC tpm2_sign_digest(EVP_PKEY *pkey, TPMT_HA *digest, TPMT_SIGNATURE *sig)
{
	EVP_PKEY_CTX *ctx;
	const int pkey_id = EVP_PKEY_id(pkey);
	size_t size;

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		return TPM_RC_MEMORY;

	EVP_PKEY_sign_init(ctx);
	EVP_PKEY_CTX_set_signature_md(ctx, tpm2_md(digest->hashAlg));
	if (pkey_id == EVP_PKEY_RSA) {
		sig->sigAlg = TPM_ALG_RSASSA;
		EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
		sig->signature.rsassa.hash = digest->hashAlg;
		size = MAX_RSA_KEY_BYTES;
		EVP_PKEY_sign(ctx, VAL_2B(sig->signature.rsassa.sig, buffer),
			      &size,
			      (uint8_t *)&digest->digest,
			      TSS_GetDigestSize(digest->hashAlg));
		VAL_2B(sig->signature.rsassa.sig, size) = size;
	} else if (pkey_id == EVP_PKEY_EC) {
		unsigned char sigbuf[1024];
		const unsigned char *p;
		ECDSA_SIG *es = ECDSA_SIG_new();
		const BIGNUM *r, *s;

		sig->sigAlg = TPM_ALG_ECDSA;
		sig->signature.ecdsa.hash = digest->hashAlg;
		size = sizeof(sigbuf);
		EVP_PKEY_sign(ctx, sigbuf, &size, (uint8_t *)&digest->digest,
			      TSS_GetDigestSize(digest->hashAlg));
		/* this is all openssl crap: it returns der form unlike RSA
		 * which returns raw form */
		p = sigbuf;
		d2i_ECDSA_SIG(&es, &p, size);
#if OPENSSL_VERSION_NUMBER < 0x10100000
		r = es->r;
		s = es->s;
#else
		r = ECDSA_SIG_get0_r(es);
		s = ECDSA_SIG_get0_s(es);
#endif
		VAL_2B(sig->signature.ecdsa.signatureR, size) =
			BN_bn2bin(r, VAL_2B(sig->signature.ecdsa.signatureR,
					    buffer));
		VAL_2B(sig->signature.ecdsa.signatureS, size) =
			BN_bn2bin(s, VAL_2B(sig->signature.ecdsa.signatureS,
					    buffer));
		ECDSA_SIG_free(es);
	} else {
		fprintf(stderr, "pkey has unknown signing algorithm %d\n", pkey_id);
		exit(1);
	}
	EVP_PKEY_CTX_free(ctx);

	return TPM_RC_SUCCESS;
}

int tpm2_load_bf(BIO *bf, struct app_data *app_data, const char *srk_auth)
{
	TSSLOADABLE *tssl = NULL;
	TSSPRIVKEY *tpk = NULL;
	BYTE *buffer;
	INT32 size;
	char oid[128];
	int empty_auth;
	enum tpm2_type tpm2_type = TPM2_NONE;
	ASN1_OBJECT *type;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	STACK_OF(TSSOPTPOLICY) *policy;
	ASN1_OCTET_STRING *privkey;
	ASN1_OCTET_STRING *secret = NULL;
	STACK_OF(TSSAUTHPOLICY) *authPolicy;

	tpk = PEM_read_bio_TSSPRIVKEY(bf, NULL, NULL, NULL);
	if (!tpk) {
		BIO_seek(bf, 0);
		ERR_clear_error();
		tpk = ASN1_item_d2i_bio(ASN1_ITEM_rptr(TSSPRIVKEY), bf, NULL);
	}
	if (tpk) {
		type = tpk->type;
		empty_auth = tpk->emptyAuth;
		parent = tpk->parent;
		pubkey = tpk->pubkey;
		privkey = tpk->privkey;
		policy = tpk->policy;
		secret = tpk->secret;
		authPolicy = tpk->authPolicy;
	} else {
		tpm2_type = TPM2_LEGACY;
		BIO_seek(bf, 0);
		tssl = PEM_read_bio_TSSLOADABLE(bf, NULL, NULL, NULL);
		if (!tssl) {
			BIO_seek(bf, 0);
			ERR_clear_error();
			tssl = ASN1_item_d2i_bio(ASN1_ITEM_rptr(TSSLOADABLE), bf, NULL);
		}

		if (!tssl)
			return 0;

		/* have error from failed TSSPRIVKEY load */
		ERR_clear_error();
		type = tssl->type;
		empty_auth = tssl->emptyAuth;
		parent = tssl->parent;
		pubkey = tssl->pubkey;
		privkey = tssl->privkey;
		policy = tssl->policy;
		authPolicy = NULL;
	}

	if (OBJ_obj2txt(oid, sizeof(oid), type, 1) == 0) {
		fprintf(stderr, "Failed to parse object type\n");
		goto err;
	}

	if (strcmp(OID_loadableKey, oid) == 0) {
		if (tpm2_type != TPM2_NONE) {
			fprintf(stderr, "New type found in old format key\n");
			goto err;
		}
		tpm2_type = TPM2_LOADABLE;
	} else if (strcmp(OID_OldloadableKey, oid) == 0) {
		if (tpm2_type != TPM2_LEGACY) {
			fprintf(stderr, "Old type found in new format key\n");
			goto err;
		}
	} else if (strcmp(OID_importableKey, oid) == 0) {
		if (!secret) {
			fprintf(stderr, "Importable keys require an encrypted secret\n");
			goto err;
		}
		tpm2_type = TPM2_IMPORTABLE;
	} else if (strcmp(OID_sealedData, oid) == 0){
		tpm2_type = TPM2_SEALED;
	} else {
		fprintf(stderr, "Unrecognised object type\n");
		goto err;
	}

	if (empty_auth == -1)
		/* not present means auth is not empty */
		empty_auth = 0;

	app_data->type = tpm2_type;
	app_data->dir = tpm2_set_unique_tssdir();

	if (parent)
		app_data->parent = ASN1_INTEGER_get(parent);
	else
		/* older keys have absent parent */
		app_data->parent = EXT_TPM_RH_OWNER;

	buffer = pubkey->data;
	size = pubkey->length;
	TPM2B_PUBLIC_Unmarshal(&app_data->Public, &buffer, &size, FALSE);

	if (secret) {
		TPM_HANDLE session;
		TPM_HANDLE parentHandle;
		DATA_2B encryptionKey;
		PRIVATE_2B duplicate;
		ENCRYPTED_SECRET_2B inSymSeed;
		TPMT_SYM_DEF_OBJECT symmetricAlg;
		TSS_CONTEXT *tssContext;
		TPM_RC rc;
		const char *reason;
		PRIVATE_2B priv_2b;
		PRIVATE_2B outPrivate;
		BYTE *buf;
		UINT16 written;
		INT32 size;

		rc = tpm2_create(&tssContext, app_data->dir);
		if (rc) {
			reason="tpm2_create";
			goto import_no_flush_err;
		}

		parentHandle = tpm2_handle_int(tssContext, app_data->parent);
		if (tpm2_handle_mso(tssContext, parentHandle, TPM_HT_PERMANENT)) {
			tpm2_load_srk(tssContext, &parentHandle,
				      srk_auth, NULL, parentHandle,
				      TPM2_LOADABLE);
		}

		rc = tpm2_get_session_handle(tssContext, &session,
					     parentHandle,
					     TPM_SE_HMAC,
					     app_data->Public.publicArea.nameAlg);
		if (rc) {
			reason="tpm2_get_session_handle";
			goto import_err;
		}

		/* no inner encryption */
		encryptionKey.size = 0;
		symmetricAlg.algorithm = TPM_ALG_NULL;

		/* for importable keys the private key is actually the
		 * outer wrapped duplicate structure */
		buffer = privkey->data;
		size = privkey->length;
		TPM2B_PRIVATE_Unmarshal((TPM2B_PRIVATE *)&duplicate,
					&buffer, &size);

		buffer = secret->data;
		size = secret->length;
		TPM2B_ENCRYPTED_SECRET_Unmarshal((TPM2B_ENCRYPTED_SECRET *)
						 &inSymSeed, &buffer, &size);
		rc = tpm2_Import(tssContext, parentHandle, &encryptionKey,
				 &app_data->Public, &duplicate, &inSymSeed,
				 &symmetricAlg, &outPrivate, session, srk_auth);
		if (rc)
			tpm2_flush_handle(tssContext, session);
		reason = "TPM2_Import";

	import_err:
		tpm2_flush_srk(tssContext, parentHandle);
	import_no_flush_err:
		TSS_Delete(tssContext);
		if (rc) {
			tpm2_error(rc, reason);
			goto err;
		}
		buf = priv_2b.buffer;
		size = sizeof(priv_2b.buffer);
		written = 0;
		TSS_TPM2B_PRIVATE_Marshal((TPM2B_PRIVATE *)&outPrivate,
					  &written, &buf, &size);
		app_data->priv = OPENSSL_malloc(written);
		if (!app_data->priv)
			goto err;
		app_data->priv_len = written;
		memcpy(app_data->priv, priv_2b.buffer, written);
	} else {
		app_data->priv = OPENSSL_malloc(privkey->length);
		if (!app_data->priv)
			goto err;

		app_data->priv_len = privkey->length;
		memcpy(app_data->priv, privkey->data, app_data->priv_len);
	}

	app_data->empty_auth = empty_auth;

	if (!(VAL(app_data->Public.publicArea.objectAttributes) &
	      TPMA_OBJECT_USERWITHAUTH))
		app_data->req_policy_session = 1;

	if (!tpm2_engine_load_key_policy(app_data, policy, authPolicy))
		goto err;

	TSSLOADABLE_free(tssl);
	TSSPRIVKEY_free(tpk);

	return 1;

 err:
	TSSLOADABLE_free(tssl);
	TSSPRIVKEY_free(tpk);

	return 0;
}

int tpm2_load_engine_file(const char *filename, struct app_data **app_data,
			  EVP_PKEY **ppkey, UI_METHOD *ui, void *cb_data,
			  const char *srk_auth, int get_key_auth,
			  int public_only)
{
	BIO *bf;
	struct app_data *ad;
	int ret;

	bf = BIO_new_file(filename, "r");
	if (!bf) {
		fprintf(stderr, "File %s does not exist or cannot be read\n",
			filename);
		return 0;
	}

	ad = OPENSSL_zalloc(sizeof(*ad));

	if (!ad) {
		fprintf(stderr, "Failed to allocate app_data\n");
		BIO_free(bf);
		return 0;
	}

	ret = tpm2_load_bf(bf, ad, srk_auth);
	BIO_free(bf);
	if (!ret)
		goto err_free;

	if (ppkey) {
		*ppkey = tpm2_to_openssl_public(&ad->Public.publicArea);
		if (!*ppkey) {
			fprintf(stderr, "Failed to allocate a new EVP_KEY\n");
			goto err_free;
		}
		if (public_only) {
			tpm2_delete(ad);
			goto out;
		}
	}

	if (ad->empty_auth == 0 && get_key_auth) {
		ad->auth = tpm2_get_auth(ui, "TPM Key Password: ", cb_data);
		if (!ad->auth)
			goto err_free_key;
	}

 out:
	*app_data = ad;

	return 1;
 err_free_key:
	if (ppkey)
		EVP_PKEY_free(*ppkey);
 err_free:
	if (ppkey)
		*ppkey = NULL;

	tpm2_delete(ad);

	return 0;
}

void tpm2_delete(struct app_data *app_data)
{
	int i, j;
	struct policies *pols = app_data->pols;

	if (pols) {
		for (i = 0; i < app_data->num_pols; i++) {
			for (j = 0; j < pols[i].num_commands; j++)
				OPENSSL_free(pols[i].commands[j].policy);

			OPENSSL_free(pols[i].commands);
			OPENSSL_free(pols[i].name);
		}
		OPENSSL_free(app_data->pols);
	}
	OPENSSL_free(app_data->priv);

	if (app_data->auth)
		OPENSSL_clear_free(app_data->auth, strlen(app_data->auth));

	tpm2_rm_keyfile(app_data->dir, app_data->parent);
	/* if key was nv key, flush may not have removed file */
	tpm2_rm_keyfile(app_data->dir, app_data->key);
	tpm2_rm_tssdir(app_data->dir);

	OPENSSL_free((void *)app_data->dir);

	OPENSSL_free(app_data);
}

TPM_HANDLE tpm2_load_key(TSS_CONTEXT **tsscp, const struct app_data *app_data,
			 const char *srk_auth, uint32_t *psrk)
{
	TSS_CONTEXT *tssContext;
	PRIVATE_2B inPrivate;
	TPM_HANDLE parentHandle;
	TPM_HANDLE key = 0;
	TPM_RC rc;
	BYTE *buffer;
	INT32 size;
	TPM_HANDLE session;

	rc = tpm2_create(&tssContext, app_data->dir);
	if (rc)
		return 0;

	if (app_data->key) {
		key = tpm2_handle_int(tssContext, app_data->key);
		goto out;
	}

	buffer = app_data->priv;
	size = app_data->priv_len;
	TPM2B_PRIVATE_Unmarshal((TPM2B_PRIVATE *)&inPrivate, &buffer, &size);

	parentHandle = tpm2_handle_int(tssContext, app_data->parent);
	if (tpm2_handle_mso(tssContext, parentHandle, TPM_HT_PERMANENT)) {
		rc = tpm2_load_srk(tssContext, &parentHandle, srk_auth, NULL,
				   parentHandle, app_data->type);
		if (rc)
			goto out;
	}
	rc = tpm2_get_session_handle(tssContext, &session, parentHandle,
				     TPM_SE_HMAC, app_data->Public.publicArea.nameAlg);
	if (rc)
		goto out_flush_srk;

	rc = tpm2_Load(tssContext, parentHandle, &inPrivate, &app_data->Public,
		       &key, session, srk_auth);
	if (rc) {
		tpm2_error(rc, "TPM2_Load");
		tpm2_flush_handle(tssContext, session);
	}

 out_flush_srk:
	if (key && psrk)
		*psrk = parentHandle;
	else
		tpm2_flush_srk(tssContext, parentHandle);
 out:
	if (!key)
		TSS_Delete(tssContext);
	else
		*tsscp = tssContext;

	return key;
}

void tpm2_unload_key(TSS_CONTEXT *tssContext, TPM_HANDLE key)
{
	tpm2_flush_handle(tssContext, key);

	TSS_Delete(tssContext);
}

TPM_HANDLE tpm2_get_parent_ext(const char *pstr)
{
	TPM_HANDLE p;

	if (strcmp(pstr, "owner") == 0)
		p = EXT_TPM_RH_OWNER;
	else if (strcmp(pstr, "platform") == 0)
		p = EXT_TPM_RH_PLATFORM;
	else if (strcmp(pstr, "endorsement") == 0)
		p = EXT_TPM_RH_ENDORSEMENT;
	else if (strcmp(pstr, "null") == 0)
		p = EXT_TPM_RH_NULL;
	else {
		p = strtoul(pstr, NULL, 16);
		if ((p >> 24) != TPM_HT_PERSISTENT)
			p = 0;
	}

	return p;
}

TPM_HANDLE tpm2_get_parent(TSS_CONTEXT *tssContext, const char *pstr)
{
	TPM_HANDLE p;

	p = tpm2_get_parent_ext(pstr);
	if (p == 0)
		return p;

	p = tpm2_handle_int(tssContext, p);

	return p;
}

int tpm2_write_tpmfile(const char *file, BYTE *pubkey, int pubkey_len,
		       BYTE *privkey, int privkey_len, int empty_auth,
		       TPM_HANDLE parent, STACK_OF(TSSOPTPOLICY) *sk,
		       int version, ENCRYPTED_SECRET_2B *secret)
{
	union {
		TSSLOADABLE tssl;
		TSSPRIVKEY tpk;
	} k;
	BIO *outb;

	/* clear structure so as not to have to set optional parameters */
	memset(&k, 0, sizeof(k));
	if ((outb = BIO_new_file(file, "w")) == NULL) {
                fprintf(stderr, "Error opening file for write: %s\n", file);
		return 1;
	}
	if (version == 0) {
		k.tssl.type = OBJ_txt2obj(OID_OldloadableKey, 1);
		/* standard requires true or not present */
		k.tssl.emptyAuth = empty_auth ? 0xff : -1;
		k.tssl.parent = ASN1_INTEGER_new();
		ASN1_INTEGER_set(k.tssl.parent, parent);

		k.tssl.pubkey = ASN1_OCTET_STRING_new();
		ASN1_STRING_set(k.tssl.pubkey, pubkey, pubkey_len);
		k.tssl.privkey = ASN1_OCTET_STRING_new();
		ASN1_STRING_set(k.tssl.privkey, privkey, privkey_len);
		k.tssl.policy = sk;

		PEM_write_bio_TSSLOADABLE(outb, &k.tssl);
	} else {
		if (version == 2) {
			k.tpk.type = OBJ_txt2obj(OID_sealedData, 1);
		} else if (secret) {
			k.tpk.type = OBJ_txt2obj(OID_importableKey, 1);
		} else {
			k.tpk.type = OBJ_txt2obj(OID_loadableKey, 1);
		}

		if (secret) {
			k.tpk.secret = ASN1_OCTET_STRING_new();
			ASN1_STRING_set(k.tpk.secret, secret->secret,
					secret->size);
		}

		/* standard requires true or not present */
		k.tpk.emptyAuth = empty_auth ? 0xff : -1;
		k.tpk.parent = ASN1_INTEGER_new();
		ASN1_INTEGER_set(k.tpk.parent, parent);

		k.tpk.pubkey = ASN1_OCTET_STRING_new();
		ASN1_STRING_set(k.tpk.pubkey, pubkey, pubkey_len);
		k.tpk.privkey = ASN1_OCTET_STRING_new();
		ASN1_STRING_set(k.tpk.privkey, privkey, privkey_len);
		k.tpk.policy = sk;

		PEM_write_bio_TSSPRIVKEY(outb, &k.tpk);
	}

	BIO_free(outb);
	return 0;
}

/* from lib/hexdump.c (Linux kernel) */
int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

int hex2bin(unsigned char *dst, const char *src, size_t count)
{
	while (count--) {
		int hi = hex_to_bin(*src++);
		int lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}

TPM_RC tpm2_parse_policy_file(const char *policy_file,
			      STACK_OF(TSSOPTPOLICY) *sk,
			      char *auth, TPMT_HA *digest)
{
	struct stat st;
	char *data, *data_ptr;
	unsigned char buf[2048];
	unsigned char *buf_ptr;
	TSSOPTPOLICY *policy = NULL;
	INT32 buf_len;
	TPM_CC code;
	TPM_RC rc = NOT_TPM_ERROR;
	int fd, policy_auth_value = 0;

	if (stat(policy_file, &st) == -1) {
		fprintf(stderr, "File %s cannot be accessed\n", policy_file);
		return rc;
	}

	fd = open(policy_file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "File %s cannot be opened\n", policy_file);
		return rc;
	}

	data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE, fd, 0);
	if (!data) {
		fprintf(stderr, "mmap() failed\n");
		goto out;
	}

	while ((data_ptr = strsep(&data, "\n"))) {
		TPMT_HA hash_digest;
		unsigned char *hash = (unsigned char *)&hash_digest.digest;
		INT32 hash_len;

		buf_ptr = buf;
		buf_len = strlen(data_ptr) / 2;
		if (buf_len > sizeof(buf)) {
			rc = NOT_TPM_ERROR;
			fprintf(stderr, "line too long\n");
			goto out_munmap;
		}

		if (!buf_len)
			break;

		rc = hex2bin(buf, data_ptr, buf_len);
		if (rc < 0) {
			rc = NOT_TPM_ERROR;
			fprintf(stderr, "hex2bin() failed\n");
			goto out_munmap;
		}

		rc = TPM_CC_Unmarshal(&code, &buf_ptr, &buf_len);
		if (rc) {
			fprintf(stderr, "TPM_CC_Unmarshal() failed\n");
			goto out_munmap;
		}

		if (code == TPM_CC_PolicyCounterTimer) {
			/* for a countertimer, the policy is a hash of the hash */
			hash_digest.hashAlg = digest->hashAlg;
			hash_len = TSS_GetDigestSize(digest->hashAlg);
			TSS_Hash_Generate(&hash_digest, buf_len, buf_ptr, 0, NULL);
			hash = (unsigned char *)&hash_digest.digest;
		} else {
			hash = buf_ptr;
			hash_len = buf_len;
		}

		rc = TSS_Hash_Generate(digest,
				       TSS_GetDigestSize(digest->hashAlg),
				       (uint8_t *)&digest->digest,
				       /* the command code */
				       4, buf_ptr - 4,
				       hash_len, hash, 0, NULL);
		if (rc) {
			fprintf(stderr, "TSS_Hash_Generate() failed\n");
			goto out_munmap;
		}

		if (code == TPM_CC_PolicyAuthValue)
			policy_auth_value = 1;

		policy = TSSOPTPOLICY_new();
		ASN1_INTEGER_set(policy->CommandCode, code);
		ASN1_STRING_set(policy->CommandPolicy, buf_ptr, buf_len);
		sk_TSSOPTPOLICY_push(sk, policy);
	}

	if (auth && !policy_auth_value) {
		rc = NOT_TPM_ERROR;
		fprintf(stderr, "PolicyAuthValue command is required\n");
	}

out_munmap:
	munmap(data, st.st_size);
out:
	close(fd);
	return rc;
}

static void tpm2_read_tpk(char *tpmkey, TSSPRIVKEY **tpk)
{
	BIO *bf;
	*tpk = NULL;

	bf = BIO_new_file(tpmkey, "r");
	if (!bf) {
		fprintf(stderr, "File %s does not exist or cannot be read\n",
			tpmkey);
		return;
	}

	*tpk = PEM_read_bio_TSSPRIVKEY(bf, NULL, NULL, NULL);
	if (!*tpk) {
		BIO_seek(bf, 0);
		ERR_clear_error();
		*tpk = ASN1_item_d2i_bio(ASN1_ITEM_rptr(TSSPRIVKEY), bf, NULL);
	}
	BIO_free(bf);
	if (!*tpk)
		fprintf(stderr, "Cannot parse file as TPM key\n");
}

static int tpm2_write_tpk(char *tpmkey, TSSPRIVKEY *tpk)
{
	BIO *bf;

	bf = BIO_new_file(tpmkey, "w");
	if (bf == NULL) {
		fprintf(stderr, "Failed to open key file %s for writing\n",
			tpmkey);
		return 1;
	}
	PEM_write_bio_TSSPRIVKEY(bf, tpk);
	BIO_free(bf);

	return 0;
}

int tpm2_rm_signed_policy(char *tpmkey, int rmnum)
{
	TSSPRIVKEY *tpk;
	TSSAUTHPOLICY *ap;
	int ret = 0;

	tpm2_read_tpk(tpmkey, &tpk);
	if (!tpk)
		return 1;

	if (sk_TSSAUTHPOLICY_num(tpk->authPolicy) < rmnum) {
		fprintf(stderr, "Policy %d does not exist\n", rmnum);
		goto out_free;
	}

	ap = sk_TSSAUTHPOLICY_delete(tpk->authPolicy, rmnum - 1);
	TSSAUTHPOLICY_free(ap);

	ret = tpm2_write_tpk(tpmkey, tpk);

 out_free:
	TSSPRIVKEY_free(tpk);
	return ret;
}

int tpm2_get_signed_policy(char *tpmkey, STACK_OF(TSSAUTHPOLICY) **sk)
{
	TSSPRIVKEY *tpk;

	*sk = NULL;
	tpm2_read_tpk(tpmkey, &tpk);
	if (!tpk)
		return 1;

	if (tpk->authPolicy) {
		*sk = sk_TSSAUTHPOLICY_dup(tpk->authPolicy);
		/* dup does not duplicate elements, so transfer ownership */
		sk_TSSAUTHPOLICY_zero(tpk->authPolicy);
	}

	TSSPRIVKEY_free(tpk);
	return 0;
}

TPM_RC tpm2_new_signed_policy(char *tpmkey, char *policykey, char *engine,
			      TSSAUTHPOLICY *ap, TPMT_HA *digest)
{
	BIO *bf;
	TSSPRIVKEY *tpk;
	EVP_PKEY *pkey;
	TSSOPTPOLICY *policy;
	BYTE *buffer;
	INT32 size;
	TPM2B_PUBLIC pub;
	DIGEST_2B nonce;
	TPMT_HA hash;
	TPM_RC rc;
	TPMT_SIGNATURE sig;
	NAME_2B name;
	const TPM_CC cc = TPM_CC_PolicyAuthorize;
	BYTE buf[1024];
	UINT16 written = 0;

	tpm2_read_tpk(tpmkey, &tpk);
	if (!tpk)
		return 0;

	if (!tpk->policy || sk_TSSOPTPOLICY_num(tpk->policy) <= 0) {
		fprintf(stderr, "TPM Key has no policy\n");
		goto err_free_tpmkey;
	}

	policy = sk_TSSOPTPOLICY_value(tpk->policy, 0);
	if (ASN1_INTEGER_get(policy->CommandCode) != TPM_CC_PolicyAuthorize) {
		fprintf(stderr, "TPM Key has no signed policy\n");
		goto err_free_tpmkey;
	}

	buffer = policy->CommandPolicy->data;
	size = policy->CommandPolicy->length;
	rc = TPM2B_PUBLIC_Unmarshal(&pub, &buffer, &size, FALSE);
	if (rc == TPM_RC_SUCCESS) {
		rc = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&nonce, &buffer, &size);
	} else {
		fprintf(stderr, "Unmarshal Failure on PolicyAuthorize public key\n");
	}

	if (rc != TPM_RC_SUCCESS) {
		fprintf(stderr, "Unmarshal failure on PolicyAuthorize\n");
		goto err_free_tpmkey;
	}

	bf = BIO_new_file(policykey, "r");
	if (!bf) {
		fprintf(stderr, "File %s does not exist or cannot be read\n",
			policykey);
		goto err_free_tpmkey;
	}

	pkey = PEM_read_bio_PrivateKey(bf, NULL, NULL, NULL);
	BIO_free(bf);
	if (!pkey) {
		fprintf(stderr, "Could not get policy private key\n");
		goto err_free_tpmkey;
	}

	/* the to be signed hash is HASH(approvedPolicy || nonce) */
	hash.hashAlg = name_alg;
	TSS_Hash_Generate(&hash,
			  TSS_GetDigestSize(digest->hashAlg), &digest->digest,
			  nonce.size, nonce.buffer,
			  0, NULL);

	rc = tpm2_sign_digest(pkey, &hash, &sig);
	EVP_PKEY_free(pkey);
	if (rc != TPM_RC_SUCCESS) {
		fprintf(stderr, "Signing failed\n");
		goto err_free_tpmkey;
	}
	tpm2_ObjectPublic_GetName(&name, &pub.publicArea);

	size = sizeof(buf);
	buffer = buf;
	TSS_TPM_CC_Marshal(&cc, &written, &buffer, &size);
	TSS_TPM2B_PUBLIC_Marshal(&pub, &written, &buffer, &size);
	TSS_TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&nonce, &written, &buffer, &size);
	TSS_TPMT_SIGNATURE_Marshal(&sig, &written, &buffer, &size);

	policy = TSSOPTPOLICY_new();

	ASN1_INTEGER_set(policy->CommandCode, cc);
	ASN1_STRING_set(policy->CommandPolicy, buf + 4, written - 4);
	sk_TSSOPTPOLICY_push(ap->policy, policy);

	if (!tpk->authPolicy)
		tpk->authPolicy = sk_TSSAUTHPOLICY_new_null();

	/* insert at the beginning on the assumption we should try
	 * latest policy addition first */
	sk_TSSAUTHPOLICY_unshift(tpk->authPolicy, ap);

	rc = tpm2_write_tpk(tpmkey, tpk);

	TSSPRIVKEY_free(tpk);
	return rc;

 err_free_tpmkey:
	TSSPRIVKEY_free(tpk);
	return 1;
}

void tpm2_free_policy(STACK_OF(TSSOPTPOLICY) *sk)
{
	TSSOPTPOLICY *policy;

	if (sk)
		while ((policy = sk_TSSOPTPOLICY_pop(sk)))
			TSSOPTPOLICY_free(policy);

	sk_TSSOPTPOLICY_free(sk);
}

static const char *get_hash_by_alg(TPM_ALG_ID alg)
{
	int i;

	for (i = 0; tpm2_hashes[i].hash; i++)
		if (tpm2_hashes[i].alg == alg)
			break;

	return tpm2_hashes[i].hash;
}

static int add_pcrs_hash(TPML_PCR_SELECTION *pcrs, char *bank)
{
	int i;
	TPM_ALG_ID alg;

	for (i = 0; tpm2_hashes[i].hash; i++)
		if (strcmp(tpm2_hashes[i].hash, bank) == 0)
			break;

	if (!tpm2_hashes[i].hash) {
		fprintf(stderr, "unknown bank in pcrs list %s\n", bank);
		exit(1);
	}
	alg = tpm2_hashes[i].alg;

	for (i = 0; i < pcrs->count; i++)
		if (pcrs->pcrSelections[i].hash == alg) {
			fprintf(stderr, "hash bank %s was already specified\n", bank);
			exit(1);
		}

	pcrs->pcrSelections[i].hash = alg;
	pcrs->pcrSelections[i].sizeofSelect = MAX_TPM_PCRS_ARRAY;
	pcrs->count++;

	return i;
}

static void update_pcrs(TPML_PCR_SELECTION *pcrs, int bank, char *str)
{
	char *sep = strchr(str, '-');
	char *endptr;
	long from, to;
	int i;

	if (sep)
		*sep = '\0';
	from = to = strtol(str, &endptr, 10);
	if (*endptr != '\0' || from < 0 || from >= MAX_TPM_PCRS)
		goto err;

	if (sep) {
		str = sep + 1;
		to = strtol(str, &endptr, 10);

		if (*endptr != '\0' || to < 0 || to >= MAX_TPM_PCRS)
			goto err;
	}
	if (to < from) {
		fprintf(stderr, "Incorrect PCR range specified %ld-%ld\n",
			from, to);
		exit(1);
	}

	for (i = from; i <= to; i++)
		pcrs->pcrSelections[bank].pcrSelect[i/8] |= (1 << (i%8));

	return;
 err:
	fprintf(stderr, "incorrect PCR specification %s\n", str);
	exit(1);
}

void tpm2_get_pcr_lock(TPML_PCR_SELECTION *pcrs, char *arg)
{
	char *sep = strchr(arg, ':');
	char *bankstr = arg;
	int bank;

	if (sep) {
		*sep = '\0';
		arg = sep + 1;
	} else {
		bankstr = "sha256";
	}
	bank = add_pcrs_hash(pcrs, bankstr);
	for (sep = strchr(arg, ','); sep; arg = sep + 1, sep = strchr(arg, ',')) {
		*sep = '\0';
		update_pcrs(pcrs, bank, arg);
	}
	update_pcrs(pcrs, bank, arg);
}

static int hash_print(const char *hash, int start, BYTE val, int k,
		      TPML_DIGEST *dl, EVP_MD_CTX *ctx)
{
	int i, j;

	for (i = 0; i < 8; i++) {
		TPM2B_DIGEST *d;
		BYTE *db;

		if ((val & (1 << i)) == 0)
			continue;

		d = &dl->digests[k++];
		db = VAL_2B_P(d, buffer);
		EVP_DigestUpdate(ctx, VAL_2B_P(d, buffer), VAL_2B_P(d, size));
		printf("%s: %02d: ", hash, start + i);
		for (j = 0; j < VAL_2B_P(d, size); j++) {
			printf("%02x", db[j]);
		}
		printf("\n");
	}
	return k;
}

static void pcr_digests_process(TPML_PCR_SELECTION *in, TPML_PCR_SELECTION *out,
				TPML_DIGEST *d, EVP_MD_CTX *ctx)
{
	int i, j, k = 0;

	for (i = 0; i < in->count; i++) {
		const char *hash = get_hash_by_alg(out->pcrSelections[i].hash);

		for (j = 0; j < MAX_TPM_PCRS_ARRAY; j++) {
			in->pcrSelections[i].pcrSelect[j] &=
				~out->pcrSelections[i].pcrSelect[j];

			k = hash_print(hash, j * 8,
				       out->pcrSelections[i].pcrSelect[j],
				       k, d, ctx);
		}
	}
}

TPM_RC tpm2_pcr_lock_policy(TSS_CONTEXT *tssContext,
			    TPML_PCR_SELECTION *pcrs,
			    STACK_OF(TSSOPTPOLICY) *sk,
			    TPMT_HA *digest)
{
	TSSOPTPOLICY *policy = TSSOPTPOLICY_new();
	TPM_RC rc;
	BYTE buf[1024];
	UINT16 written = 0;
	INT32 size = sizeof(buf);
	const TPM_CC cc = TPM_CC_PolicyPCR;
	DIGEST_2B pcrDigest;
	BYTE *buffer = buf;
	TPML_PCR_SELECTION pcrread, pcrreturn;
	TPML_DIGEST pcr_digests;
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();

	EVP_DigestInit_ex(ctx, tpm2_md(digest->hashAlg), NULL);

	pcrread = *pcrs;

	for (;;) {
		rc = tpm2_PCR_Read(tssContext, &pcrread, &pcrreturn, &pcr_digests);
		if (pcr_digests.count == 0 || rc != TPM_RC_SUCCESS)
			break;

		pcr_digests_process(&pcrread, &pcrreturn, &pcr_digests, ctx);
	}

	EVP_DigestFinal_ex(ctx, pcrDigest.buffer, NULL);
	pcrDigest.size = TSS_GetDigestSize(digest->hashAlg);
	EVP_MD_CTX_destroy(ctx);

	if (rc)
		return rc;

	ASN1_INTEGER_set(policy->CommandCode, cc);
	TSS_TPM_CC_Marshal(&cc, &written, &buffer, &size);
	TSS_TPML_PCR_SELECTION_Marshal(pcrs, &written, &buffer, &size);
	memcpy(buffer, pcrDigest.buffer, pcrDigest.size);
	written += pcrDigest.size;
	ASN1_STRING_set(policy->CommandPolicy, buf + 4, written - 4);
	sk_TSSOPTPOLICY_push(sk, policy);

	TSS_Hash_Generate(digest,
			  TSS_GetDigestSize(digest->hashAlg),
			  (uint8_t *)&digest->digest,
			  written, buf, 0, NULL);

	return TPM_RC_SUCCESS;
}

void tpm2_add_auth_policy(STACK_OF(TSSOPTPOLICY) *sk, TPMT_HA *digest)
{
	TSSOPTPOLICY *policy = TSSOPTPOLICY_new();
	BYTE buf[4];
	BYTE *buffer = buf;
	UINT16 written = 0;
	INT32 size = sizeof(buf);
	const TPM_CC cc = TPM_CC_PolicyAuthValue;

	TSS_TPM_CC_Marshal(&cc, &written, &buffer, &size);

	ASN1_INTEGER_set(policy->CommandCode, cc);
	ASN1_STRING_set(policy->CommandPolicy, "", 0);
	sk_TSSOPTPOLICY_push(sk, policy);

	TSS_Hash_Generate(digest,
			  TSS_GetDigestSize(digest->hashAlg),
			  (uint8_t *)&digest->digest,
			  written, buf, 0, NULL);
}

void tpm2_add_locality(STACK_OF(TSSOPTPOLICY) *sk, UINT8 locality,
		       TPMT_HA *digest)
{
	TSSOPTPOLICY *policy = TSSOPTPOLICY_new();
	BYTE buf[5];
	BYTE *buffer = buf;
	UINT16 written = 0;
	INT32 size = sizeof(buf);
	const TPM_CC cc = TPM_CC_PolicyLocality;

	TSS_TPM_CC_Marshal(&cc, &written, &buffer, &size);
	TSS_UINT8_Marshal(&locality, &written, &buffer, &size);

	ASN1_INTEGER_set(policy->CommandCode, cc);
	ASN1_STRING_set(policy->CommandPolicy, buf + 4, written - 4);

	sk_TSSOPTPOLICY_push(sk, policy);

	TSS_Hash_Generate(digest,
			  TSS_GetDigestSize(digest->hashAlg),
			  (uint8_t *)&digest->digest,
			  written, buf, 0, NULL);
}

TPM_RC tpm2_add_signed_policy(STACK_OF(TSSOPTPOLICY) *sk, char *key_file,
			      TPMT_HA *digest)
{
	TSSOPTPOLICY *policy = TSSOPTPOLICY_new();
	BYTE buf[1024];
	BYTE *buffer = buf;
	UINT16 written = 0;
	INT32 size = sizeof(buf);
	const TPM_CC cc = TPM_CC_PolicyAuthorize;
	EVP_PKEY *pkey = openssl_read_public_key(key_file);
	TPM_RC rc = NOT_TPM_ERROR;
	TPM2B_PUBLIC pub;
	DIGEST_2B nonce;
	TPMT_SIGNATURE sig;
	NAME_2B name;

	if (!pkey)
		/* openssl_read_public_key will print error */
		return rc;

	rc = openssl_to_tpm_public(&pub, pkey);
	if (rc)
		return rc;
	/*
	 * Our RSA keys have a decrypt only template, so add signing to
	 * prevent TPM2_VerifySignature returning TPM_RC_ATTRIBUTES
	 */
	VAL(pub.publicArea.objectAttributes) |= TPMA_OBJECT_SIGN;

	tpm2_ObjectPublic_GetName(&name, &pub.publicArea);

	nonce.size = TSS_GetDigestSize(name_alg);
	rc = RAND_bytes(nonce.buffer, nonce.size);
	if (!rc)
		return NOT_TPM_ERROR;

	sig.sigAlg = TPM_ALG_NULL; /* should produce an empty signature */

	TSS_TPM_CC_Marshal(&cc, &written, &buffer, &size);
	TSS_TPM2B_PUBLIC_Marshal(&pub, &written, &buffer, &size);
	TSS_TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&nonce, &written, &buffer, &size);
	TSS_TPMT_SIGNATURE_Marshal(&sig, &written, &buffer, &size);

	ASN1_INTEGER_set(policy->CommandCode, cc);
	ASN1_STRING_set(policy->CommandPolicy, buf + 4, written - 4);
	sk_TSSOPTPOLICY_push(sk, policy);

	/* now we need two hashes for the policy update */


	TSS_Hash_Generate(digest,
			  TSS_GetDigestSize(digest->hashAlg),
			  (uint8_t *)&digest->digest,
			  4, buf, /* CC */
			  name.size, name.name, /* name */
			  0, NULL);

	TSS_Hash_Generate(digest,
			  TSS_GetDigestSize(digest->hashAlg),
			  (uint8_t *)&digest->digest, /* intermediate digest */
			  nonce.size, nonce.buffer,
			  0, NULL);

	return TPM_RC_SUCCESS;
}

EVP_PKEY *
openssl_read_public_key(char *filename)
{
        BIO *b = NULL;
	EVP_PKEY *pkey;

        b = BIO_new_file(filename, "r");
        if (b == NULL) {
                fprintf(stderr, "Error opening file for read: %s\n", filename);
                return NULL;
        }

        if ((pkey = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL)) == NULL) {
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
	VAL(pub->objectAttributes) =
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_USERWITHAUTH;
	VAL_2B(pub->authPolicy, size) = 0;
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
	VAL(pub->objectAttributes) =
		TPMA_OBJECT_SIGN |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_USERWITHAUTH;
	VAL_2B(pub->authPolicy, size) = 0;
	pub->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	pub->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	pub->parameters.eccDetail.curveID = curve;
	pub->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	VAL_2B(pub->unique.ecc.x, size) = 0;
	VAL_2B(pub->unique.ecc.y, size) = 0;
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
	int order;

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

	order = tpm2_curve_to_order(curve);
	VAL_2B(pub->unique.ecc.x, size) =
		BN_bn2binpad(x, VAL_2B(pub->unique.ecc.x, buffer), order);
	VAL_2B(pub->unique.ecc.y, size) =
		BN_bn2binpad(y, VAL_2B(pub->unique.ecc.y, buffer), order);

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

	VAL_2B(pub->unique.rsa, size) =
		BN_bn2bin(n, VAL_2B(pub->unique.rsa, buffer));

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

TPM_RC tpm2_outerwrap(EVP_PKEY *parent,
		      TPMT_SENSITIVE *s,
		      TPMT_PUBLIC *pub,
		      PRIVATE_2B *p,
		      ENCRYPTED_SECRET_2B *enc_secret)
{
	PRIVATE_2B secret, seed;
	/*  amount of room in the buffer for the integrity TPM2B */
	const int integrity_skip = SHA256_DIGEST_LENGTH + 2;
	//	BYTE *integrity = p->buffer;
	BYTE *sensitive = p->buffer + integrity_skip;
	BYTE *buf;
	TPM2B *t2b;
	INT32 size;
	size_t ssize;
	UINT16 bsize, written = 0;
	EVP_PKEY *ephemeral = NULL;
	EVP_PKEY_CTX *ctx;
	TPM2B_ECC_POINT pub_pt, ephemeral_pt;
	EC_KEY *e_parent, *e_ephemeral;
	const EC_GROUP *group;
	unsigned char aeskey[T2_AES_KEY_BYTES];
	/* hmac follows namealg, so set to max size */
	KEY_2B hmackey;
	TPMT_HA hmac;
	NAME_2B name;
	DIGEST_2B digest;
	unsigned char null_iv[AES_128_BLOCK_SIZE_BYTES];
	TPM2B null_2b;

	null_2b.size = 0;

	if (EVP_PKEY_type(EVP_PKEY_id(parent)) != EVP_PKEY_EC) {
		printf("Can only currently wrap to EC parent\n");
		return TPM_RC_ASYMMETRIC;
	}

	e_parent = EVP_PKEY_get1_EC_KEY(parent);
	group = EC_KEY_get0_group(e_parent);

	/* marshal the sensitive into a TPM2B */
	t2b = (TPM2B *)sensitive;
	buf = t2b->buffer;
	size = sizeof(p->buffer) - integrity_skip;
	bsize = 0;
	TSS_TPMT_SENSITIVE_Marshal(s, &bsize, &buf, &size);
	buf = (BYTE *)&t2b->size;
	size = 2;
	TSS_UINT16_Marshal(&bsize, &written, &buf, &size);
	/* set the total size of the private entity */
	p->size = bsize + sizeof(UINT16) + integrity_skip;

	/* compute the elliptic curve shared (and encrypted) secret */
	ctx = EVP_PKEY_CTX_new(parent, NULL);
	if (!ctx)
		goto openssl_err;
	if (EVP_PKEY_keygen_init(ctx) != 1)
		goto openssl_err;
	EVP_PKEY_keygen(ctx, &ephemeral);
	if (!ephemeral)
		goto openssl_err;
	/* otherwise the ctx free will free the key */
#if OPENSSL_VERSION_NUMBER < 0x10100000
	CRYPTO_add(&ephemeral->references, 1, CRYPTO_LOCK_EVP_PKEY);
#else
	EVP_PKEY_up_ref(ephemeral);
#endif
	EVP_PKEY_CTX_free(ctx);

	e_ephemeral = EVP_PKEY_get1_EC_KEY(ephemeral);

	/* now begin again with the ephemeral private key because the
	 * context must be initialised with the private key */
	ctx = EVP_PKEY_CTX_new(ephemeral, NULL);
	if (!ctx)
		goto openssl_err;
	if (EVP_PKEY_derive_init(ctx) != 1)
		goto openssl_err;
	if (EVP_PKEY_derive_set_peer(ctx, parent) != 1)
		goto openssl_err;
	ssize = sizeof(secret.buffer);
	if (EVP_PKEY_derive(ctx, secret.buffer, &ssize) != 1)
		goto openssl_err;
	secret.size = ssize;
	EVP_PKEY_CTX_free(ctx);

	tpm2_get_public_point(&pub_pt, group, EC_KEY_get0_public_key(e_parent));
	tpm2_get_public_point(&ephemeral_pt, group,
			      EC_KEY_get0_public_key(e_ephemeral));
	EC_KEY_free(e_parent);
	EC_KEY_free(e_ephemeral);

	/* now pass the secret through KDFe to get the shared secret
	 * The size is the size of the parent name algorithm which we
	 * assume to be sha256 */
	TSS_KDFE(seed.buffer, TPM_ALG_SHA256, (TPM2B *)&secret, "DUPLICATE",
		 (TPM2B *)&ephemeral_pt.point.x, (TPM2B *)&pub_pt.point.x,
		 SHA256_DIGEST_LENGTH*8);
	seed.size = SHA256_DIGEST_LENGTH;

	/* and finally through KDFa to get the aes symmetric encryption key */
	tpm2_ObjectPublic_GetName(&name, pub);
	TSS_KDFA(aeskey, TPM_ALG_SHA256, (TPM2B *)&seed, "STORAGE",
		 (TPM2B *)&name, &null_2b, T2_AES_KEY_BITS);
	/* and then the outer HMAC key */
	hmackey.size = SHA256_DIGEST_LENGTH;
	TSS_KDFA(hmackey.buffer, TPM_ALG_SHA256, (TPM2B *)&seed, "INTEGRITY",
		 &null_2b, &null_2b, SHA256_DIGEST_LENGTH*8);
	/* OK the ephermeral public point is now the encrypted secret */
	size = sizeof(ephemeral_pt);
	written = 0;
	buf = enc_secret->secret;
	TSS_TPM2B_ECC_POINT_Marshal(&ephemeral_pt, &written,
				    &buf, &size);
	enc_secret->size = written;
	memset(null_iv, 0, sizeof(null_iv));
	TSS_AES_EncryptCFB(sensitive, T2_AES_KEY_BITS, aeskey, null_iv,
			   p->size - integrity_skip, sensitive);
	hmac.hashAlg = TPM_ALG_SHA256;
	TSS_HMAC_Generate(&hmac, (TPM2B_KEY *)&hmackey,
			  p->size - integrity_skip, sensitive,
			  name.size, name.name,
			  0, NULL);
	digest.size  = SHA256_DIGEST_LENGTH;
	memcpy(digest.buffer, &hmac.digest, digest.size);
	size = integrity_skip;
	buf = p->buffer;
	TSS_TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&digest, &written, &buf, &size);
	return TPM_RC_SUCCESS;

 openssl_err:
	ERR_print_errors_fp(stderr);
	return TPM_RC_ASYMMETRIC;
}

void
openssl_print_errors()
{
	ERR_load_ERR_strings();
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
}

IMPLEMENT_ASN1_FUNCTIONS(TSSOPTPOLICY)
IMPLEMENT_ASN1_FUNCTIONS(TSSAUTHPOLICY)
IMPLEMENT_ASN1_FUNCTIONS(TSSLOADABLE)
IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY)
IMPLEMENT_PEM_write_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE)
IMPLEMENT_PEM_read_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE)
IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY)
IMPLEMENT_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY)

ASN1_SEQUENCE(TSSOPTPOLICY) = {
	ASN1_EXP(TSSOPTPOLICY, CommandCode, ASN1_INTEGER, 0),
	ASN1_EXP(TSSOPTPOLICY, CommandPolicy, ASN1_OCTET_STRING, 1)
} ASN1_SEQUENCE_END(TSSOPTPOLICY)

ASN1_SEQUENCE(TSSAUTHPOLICY) = {
	ASN1_EXP_OPT(TSSAUTHPOLICY, name, ASN1_UTF8STRING, 0),
	ASN1_EXP_SEQUENCE_OF(TSSAUTHPOLICY, policy, TSSOPTPOLICY, 1)
} ASN1_SEQUENCE_END(TSSAUTHPOLICY)

ASN1_SEQUENCE(TSSLOADABLE) = {
	ASN1_SIMPLE(TSSLOADABLE, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSLOADABLE, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_EXP_OPT(TSSLOADABLE, parent, ASN1_INTEGER, 1),
	ASN1_EXP_OPT(TSSLOADABLE, pubkey, ASN1_OCTET_STRING, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSLOADABLE, policy, TSSOPTPOLICY, 3),
	ASN1_SIMPLE(TSSLOADABLE, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSLOADABLE)

ASN1_SEQUENCE(TSSPRIVKEY) = {
	ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSPRIVKEY, policy, TSSOPTPOLICY, 1),
	ASN1_EXP_OPT(TSSPRIVKEY, secret, ASN1_OCTET_STRING, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSPRIVKEY, authPolicy, TSSAUTHPOLICY, 3),
	ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
	ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
	ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY)

