/*
 *
 *   Copyright (C) 2024 James Bottomley <James.Bottomley@HansenPartnership.com>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "tpm2-tss.h"
#include "tpm2-asn.h"
#include "tpm2-common.h"

/*
 *
 * --eksign [--name <namefile>] [--file <file>]
 *
 * create P-256 EK signing key and check the name against <namefile>
 * If name check is requested and passes, output the pem public key to <file>.
 *
 * --attest  <certfile> [--name <namefile>] [--file <file>]
 *
 * derive the EK signing key and verify its name against <namefile>
 * (if present).  Then attest it as a signing key against the EK
 * certificate in <certfile> using makecredential/activate credential.
 * Optionally output the pub pem to <file> if the certification
 * works.
 *
 * --certify <h> --name <ekname> [--outname] [--file <file>] [<hname>]
 *
 * derive the storage primary in hierarchy <h> and validate the name
 * against that in the <hname> file if present.  If it validates (or
 * hname is not present), derive the EK P-256 signing key and validate
 * the EK name is <ekname>. Finally, certify the key derived from <h>
 * using EK which proves the TPM knows the secret part of EK if the
 * certification signature verifies and that <h> is genuine.  If the
 * signature verifies, return success and optionally output the PEM
 * form of the public key of <h> to <file> and print the name.
 *
 */

static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"auth", 1, 0, 'a'},
	{"password", 1, 0, 'k'},
	{"eksign", 0, 0, 'E'},
	{"attest", 1, 0, 'A'},
	{"certify", 1, 0, 'C'},
	{"name", 1, 0, 'n'},
	{"outname", 0, 0, 'o'},
	{"file", 1, 0, 'f'},
	{0, 0, 0, 0}
};

void
usage(char *argv0)
{
	fprintf(stdout, "Usage: %s {--eksign|--attest|--certify} [options]\n\n"
		"Options:\n"
		"\t-E, --eksign                  construct a restricted signing EK and\n"
		"\t                              output its name in hex if no other options\n"
		"\t                              are given.\n"
		"\t-A, --attest <certfile>       Attest the ek signing key based on the EK\n"
		"\t                              certificate (in <certfile>) to prove it\n"
		"\t                              is genuine.\n"
		"\t-C, --certify <handle>        construct the restricted storage key for\n"
		"\t                              <handle> and certify it against the EK\n"
		"\t                              signing key.  The name file for the EK\n"
		"\t                              signing key must be provided.\n"
		"\t-h, --help                    print this help message.\n"
		"\t-a, --auth                    provide EK authorization.\n"
		"\t-k, --password <pwd>          use this password instead of prompting.\n"
		"\t-n, --name <file>             force the checking of the constructed\n"
		"\t                              hierarchy signing key against the name\n"
		"\t                              in the give file.  Fail if they do not\n"
		"\t                              match.\n"
		"\t-f, --file <file>             Output the constructed hierarchy signing\n"
		"\t                              or storage public key as a PEM file\n"
		"\t                              suitable for import or external\n"
		"\t                              cryptosystem use.\n"
		"\t-o, --outname                 Print out the name of the certified key\n"
		"\n"
		"Report bugs to " PACKAGE_BUGREPORT "\n",
		argv0);
	exit(-1);
}

static int verify_hexname(const char *namefile, char hexname[MAX_HEXNAME])
{
	int fd;
	struct stat st;
	const int len = strlen(hexname);
	int rc = NOT_TPM_ERROR;
	char name[MAX_HEXNAME];

	if (stat(namefile, &st) == -1) {
		fprintf(stderr, "File %s cannot be accessed\n", namefile);
		return rc;
	}

	/* sysfs null name is always 4096 to stat, so only check for too small */
	if (st.st_size < len) {
		fprintf(stderr, "Name file is too small should be at least %d\n",
			len);
		return rc;
	}

	fd = open(namefile, O_RDONLY);
	if (fd < 0) {
		perror("namefile can't be opened");
		return rc;
	}

	if (!read(fd, name, len)) {
		perror("namefile can't be read");
		goto out_close;
	}

	if (memcmp(name, hexname, len) == 0)
		rc = 0;
 out_close:
	close(fd);

	return rc;
}

static int write_pubkey(const char *file, TPMT_PUBLIC *pub)
{
	BIO *bf;
	int rc;
	EVP_PKEY *pkey = tpm2_to_openssl_public(pub);

	if (!pkey)
		goto openssl_err;
	bf = BIO_new_file(file, "w");
	if (!bf)
		goto openssl_err;
	rc = PEM_write_bio_PUBKEY(bf, pkey);
	BIO_free(bf);
	if (!rc)
		goto openssl_err;

	EVP_PKEY_free(pkey);
	return 0;

 openssl_err:
	ERR_print_errors_fp(stderr);
	if (pkey)
		EVP_PKEY_free(pkey);
	return NOT_TPM_ERROR;
}

/* analogue of tpm2_sign_digest from tpm2-common.c */
static TPM_RC tpm2_verify_digest(EVP_PKEY *pkey, TPMT_HA *digest,
				 TPMT_SIGNATURE *sig)
{
	EVP_PKEY_CTX *ctx;
	ECDSA_SIG *esig;
	BIGNUM *r, *s;
	unsigned char *p = NULL;
	int p_len;
	TPM_RC rc = NOT_TPM_ERROR;

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		goto openssl_err;
	esig = ECDSA_SIG_new();
	if (!esig)
		goto openssl_ctx;

	r = BN_bin2bn(VAL_2B(sig->signature.ecdsa.signatureR, buffer),
		      VAL_2B(sig->signature.ecdsa.signatureR, size), NULL);
	s = BN_bin2bn(VAL_2B(sig->signature.ecdsa.signatureS, buffer),
		      VAL_2B(sig->signature.ecdsa.signatureS, size), NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	esig->r = r;
	esig->s = s;
#else
	ECDSA_SIG_set0(esig, r, s);
#endif

	p_len = i2d_ECDSA_SIG(esig, &p);
	ECDSA_SIG_free(esig);

	EVP_PKEY_verify_init(ctx);

	if (EVP_PKEY_verify(ctx, p, p_len, (unsigned char *)&digest->digest,
			    SHA256_DIGEST_LENGTH) == 1)
		rc = 0;

	OPENSSL_free(p);

 openssl_ctx:
	EVP_PKEY_CTX_free(ctx);

 openssl_err:
	if (rc)
		ERR_print_errors_fp(stderr);
	return rc;
}

void do_certify(const char *auth, TPM_HANDLE handle, const char *namefile,
		const char *file, const char *hname, int outname)
{
	TPM_HANDLE h, ek;
	TPM2B_PUBLIC pubh, pubek;
	char hexname[MAX_HEXNAME];
	const char *dir = tpm2_set_unique_tssdir();
	TSS_CONTEXT *tssContext;
	int rc;
	DATA_2B qualifying;
	ATTEST_2B att;
	TPMT_SIGNATURE sig;
	EVP_PKEY *pkey;
	TPMT_HA digest;
	TPMS_ATTEST a;
	NAME_2B tmpname;

	if (!namefile) {
		fprintf(stderr, "signing EK name must be specified in --name argument\n");
		exit(1);
	}

	rc = tpm2_create(&tssContext, dir);
	if (rc)
		goto out_rmdir;

	handle = tpm2_handle_int(tssContext, handle);

	/*
	 * FIXME: Assumption here is that only the endorsement
	 * hierarchy may have an authority password.  However, this
	 * could be true of the owner hierarchy as well so might need
	 * an additional password parameter.
	 */
	rc = tpm2_load_srk(tssContext, &h, NULL, &pubh, handle,
			   TPM2_LOADABLE);
	if (rc)
		goto out_delete;

	if (hname) {
		tpm2_get_hexname(hexname, &pubh);
		rc = verify_hexname(hname, hexname);
		if (rc) {
			fprintf(stderr, "Error: Handle for certification failed name verification\n");
			goto out_free_h;
		}
	}

	rc = tpm2_load_srk(tssContext, &ek, auth, &pubek, TPM_RH_ENDORSEMENT,
			   TPM2_SIGNING);
	if (rc)
		goto out_free_h;

	tpm2_get_hexname(hexname, &pubek);
	rc = verify_hexname(namefile, hexname);
	if (rc) {
		fprintf(stderr, "Error: signing EK failed name verification\n");
			goto out_free_ek;
	}
	qualifying.size = SHA256_DIGEST_LENGTH;
	RAND_bytes(qualifying.buffer, qualifying.size);

	rc = tpm2_Certify(tssContext, h, ek, &qualifying, &att, &sig);
	if (rc) {
		tpm2_error(rc, "TPM2_Certify");
		goto out_free_ek;
	}

	pkey = tpm2_to_openssl_public(&pubek.publicArea);
	if (!pkey)
		goto out_free_ek;

	digest.hashAlg = TPM_ALG_SHA256;
	TSS_Hash_Generate(&digest,
			  att.size, att.attestationData,
			  0, NULL);
	rc = tpm2_verify_digest(pkey, &digest, &sig);
	if (rc) {
		fprintf(stderr, "verification of the cerification signature failed\n");
		goto out_free_ek;
	}

	/*
	 * just proving the signature isn't enough, we need to verify
	 * the expected values in the attestation area to make sure
	 * this isn't a replay and that an attacker hasn't returned to
	 * us a genuinely signed and qualified attestation report
	 * containing differet keys.
	 */
	{
		BYTE *buffer = att.attestationData;
		INT32 size = att.size;

		rc = TPMS_ATTEST_Unmarshal(&a, &buffer, &size);
	}
	if (rc) {
		tpm2_error(rc, "Unmarshalling attestation data");
		goto out_free_ek;
	}

	rc = NOT_TPM_ERROR;

	if (a.type != TPM_ST_ATTEST_CERTIFY) {
		fprintf(stderr, "Error: Attestation isn't for certification\n");
		goto out_free_ek;
	}

	if (memcmp(qualifying.buffer, VAL_2B(a.extraData, buffer),
		   qualifying.size) != 0) {
		fprintf(stderr, "Error: qualifying data is not correct\n");
		goto out_free_ek;
	}

	{
		/* construct qualifiedName for EK */
		NAME_2B ekn;
		BYTE buffer[sizeof(TPM_HANDLE)];
		BYTE *buf = buffer;
		UINT16 written =0;
		INT32 size = sizeof(buffer);
		const TPM_HANDLE perm_ek = EXT_TPM_RH_ENDORSEMENT;

		tpm2_ObjectPublic_GetName(&ekn, &pubek.publicArea);
		TSS_TPM_HANDLE_Marshal(&perm_ek, &written, &buf, &size);
		digest.hashAlg = TPM_ALG_SHA256;
		TSS_Hash_Generate(&digest,
				  written, buffer,
				  ekn.size, ekn.name,
				  0, NULL);

		/* copy the leading hash algorithm */
		memcpy(tmpname.name, ekn.name, 2);
		memcpy(&tmpname.name[2], (char *)&digest.digest,
		       SHA256_DIGEST_LENGTH);

		if (memcmp(VAL_T(a.qualifiedSigner, name),
			   tmpname.name, VAL_T(a.qualifiedSigner, size)) != 0) {
			fprintf(stderr, "Error: qualified signer does not match EK\n");
			goto out_free_ek;
		}
	}

	/* finally the certified key name */
	tpm2_ObjectPublic_GetName(&tmpname, &pubh.publicArea);
	if (memcmp(VAL_T(a.attested.certify.name, name),
		   tmpname.name, tmpname.size) != 0) {
		fprintf(stderr, "Error: certified object name  does not match\n");
		goto out_free_ek;
	}

	if (outname) {
		tpm2_get_hexname(hexname, &pubh);
		printf("%s\n", hexname);
	} else {
		printf("Good certification from TPM at %lu.%04d reset count %u\n",
		       a.clockInfo.clock/1000, (int)(a.clockInfo.clock%1000),
		       a.clockInfo.resetCount);
	}
	rc = 0;
	if (file)
		rc = write_pubkey(file, &pubh.publicArea);

 out_free_ek:
	tpm2_flush_srk(tssContext, ek);
 out_free_h:
	tpm2_flush_srk(tssContext, h);
 out_delete:
	TSS_Delete(tssContext);
 out_rmdir:
	if (dir)
		rmdir(dir);

	if (rc)
		exit(1);
}

void do_ek(const char *auth, const char *namefile, const char *file)
{
	const char *dir = tpm2_set_unique_tssdir();
	TSS_CONTEXT *tssContext;
	TPM_RC rc;
	TPM_HANDLE h;
	TPM2B_PUBLIC pub;
	char hexname[MAX_HEXNAME];

	if (file && !namefile) {
		fprintf(stderr, "for output of public key, require namefile to verify\n");
		exit(1);
	}

	rc = tpm2_create(&tssContext, dir);
	if (rc)
		goto out_rmdir;
	rc = tpm2_load_srk(tssContext, &h, auth, &pub, TPM_RH_ENDORSEMENT,
			   TPM2_SIGNING);
	tpm2_flush_srk(tssContext, h);
	if (rc)
		goto out_delete;

	tpm2_get_hexname(hexname, &pub);

	if (namefile) {
		rc = verify_hexname(namefile, hexname);
		if (rc)
			fprintf(stderr, "Error: signing EK failed name verification\n");
	} else {
		printf("%s\n", hexname);
	}

	if (file)
		rc = write_pubkey(file, &pub.publicArea);

 out_delete:
	TSS_Delete(tssContext);
 out_rmdir:
	if (dir)
		rmdir(dir);

	if (rc)
		exit(1);
}

/*
 * Try to find a template to construct the EK matching pkey
 */
static const unsigned char tcgPolicy[][SHA256_DIGEST_LENGTH] = {
	/* Policy A - Low */
	{
		0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
		0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
		0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
		0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
	},
	/* Policy B - High */
	{
		0xca, 0x3d, 0x0a, 0x99, 0xa2, 0xb9, 0x39, 0x06,
		0xf7, 0xa3, 0x34, 0x24, 0x14, 0xef, 0xcf, 0xb3,
		0xa3, 0x85, 0xd4, 0x4c, 0xd1, 0xfd, 0x45, 0x90,
		0x89, 0xd1, 0x9b, 0x50, 0x71, 0xc0, 0xb7, 0xa0,
	},
	/* Policy C - B is OR of A and C */
	{
		0x37, 0x67, 0xe2, 0xed, 0xd4, 0x3f, 0xf4, 0x5a,
		0x3a, 0x7e, 0x1e, 0xae, 0xfc, 0xef, 0x78, 0x64,
		0x3d, 0xca, 0x96, 0x46, 0x32, 0xe7, 0xaa, 0xd8,
		0x2c, 0x67, 0x3a, 0x30, 0xd8, 0x63, 0x3f, 0xde,
	},
};

void get_template(EVP_PKEY *pkey, TPMT_PUBLIC *tmpl, int high)
{
	tmpl->nameAlg = TPM_ALG_SHA256;
	VAL(tmpl->objectAttributes) = TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_ADMINWITHPOLICY |
		TPMA_OBJECT_RESTRICTED |
		TPMA_OBJECT_DECRYPT;
	if (high)
		VAL(tmpl->objectAttributes) |=
			TPMA_OBJECT_USERWITHAUTH;
	VAL_T(tmpl->authPolicy, size) = sizeof(tcgPolicy[high]);
	memcpy(&VAL_T(tmpl->authPolicy, buffer), tcgPolicy[high],
		       sizeof(tcgPolicy[high]));
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		tmpl->type = TPM_ALG_RSA;
		tmpl->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
		tmpl->parameters.rsaDetail.symmetric.keyBits.aes = 128;
		tmpl->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
		tmpl->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
		tmpl->parameters.rsaDetail.scheme.details.anySig.hashAlg = 0;
		tmpl->parameters.rsaDetail.keyBits = 2048;
		tmpl->parameters.rsaDetail.exponent = 0;
		if (high) {
			VAL_T(tmpl->unique.rsa, size) = 0;
		} else {
			VAL_T(tmpl->unique.rsa, size) = 256;
			memset(VAL_T(tmpl->unique.rsa, buffer), 0, 256);
		}
		break;
	case EVP_PKEY_EC:
		tmpl->type = TPM_ALG_ECC;
		tmpl->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
		tmpl->parameters.eccDetail.symmetric.keyBits.aes = 128;
		tmpl->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
		tmpl->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
		tmpl->parameters.eccDetail.scheme.details.anySig.hashAlg = 0;
		tmpl->parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
		tmpl->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		tmpl->parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;
		if (high) {
			VAL_T(tmpl->unique.ecc.x, size) = 0;
			VAL_T(tmpl->unique.ecc.y, size) = 0;
		} else {
			VAL_T(tmpl->unique.ecc.x, size) = 32;
			memset(VAL_T(tmpl->unique.ecc.x, buffer), 0, 32);
			VAL_T(tmpl->unique.ecc.y, size) = 32;
			memset(VAL_T(tmpl->unique.ecc.y, buffer), 0, 32);
		}
		break;
	default:
		fprintf(stderr, "Unknown certificate key type\n");
		exit(1);
	}
}

int load_ek(TSS_CONTEXT *tssContext, TPM_HANDLE *h, int *highp,
	    const char *auth, EVP_PKEY *pkey)
{
	TPM2B_PUBLIC tmpl, target, pub;
	TPM_RC rc;
	int high;

	rc = openssl_to_tpm_public(&target, pkey);

	for (high = 0; high < 2; high++) {
		get_template(pkey, &tmpl.publicArea, high);

		rc = tpm2_load_srk_tmpl(tssContext, h, auth, &tmpl, &pub,
					TPM_RH_ENDORSEMENT);
		if (rc)
			return rc;

		if (target.publicArea.type == TPM_ALG_RSA &&
		    memcmp(VAL_T(target.publicArea.unique.rsa, buffer),
			   VAL_T(pub.publicArea.unique.rsa, buffer),
			   VAL_T(target.publicArea.unique.rsa, size)) == 0)
			break;
		else if (target.publicArea.type == TPM_ALG_ECC &&
			 memcmp(VAL_T(target.publicArea.unique.ecc.x, buffer),
				VAL_T(pub.publicArea.unique.ecc.x, buffer),
				VAL_T(target.publicArea.unique.ecc.x, size)) == 0
			 &&
			 memcmp(VAL_T(target.publicArea.unique.ecc.x, buffer),
				VAL_T(pub.publicArea.unique.ecc.x, buffer),
				VAL_T(target.publicArea.unique.ecc.x, size)) == 0)
			break;

		tpm2_flush_srk(tssContext, *h);
		*h = 0;
	}

	if (*h == 0) {
		fprintf(stderr, "Error: Can't find EK matching certificate\n");
		return TPM_RC_ASYMMETRIC;
	}
	*highp = high;

	return rc;
}

void do_attest(const char *auth, const char *namefile, const char *file,
	       const char *certfile)
{
	const char *dir = tpm2_set_unique_tssdir();
	TSS_CONTEXT *tssContext;
	BIO *bf;
	X509 *x;
	EVP_PKEY *pkey;
	NAME_2B eksignname;
	PRIVATE_2B private;
	ENCRYPTED_SECRET_2B enc_secret;
	uint8_t challenge[SHA256_DIGEST_LENGTH];
	TPM_HANDLE ek, eksign;
	TPM_RC rc = NOT_TPM_ERROR;
	TPM2B_PUBLIC pubeksign;
	char hexname[MAX_HEXNAME];
	DIGEST_2B digest;
	const int integrity_skip = SHA256_DIGEST_LENGTH + 2;
	TPM_HANDLE policy;
	BYTE *buf;
	INT32 size;
	UINT16 written = 0;
	int high;

	bf = BIO_new_file(certfile, "r");
	if (!bf)
		goto out;

	x = PEM_read_bio_X509(bf, NULL, NULL, NULL);
	if (!x) {
		BIO_reset(bf);
		x = d2i_X509_bio(bf, NULL);
	}
	BIO_free(bf);
	if (!x) {
		X509_free(x);
		goto out;
	}
	ERR_clear_error();
	pkey = X509_get_pubkey(x);
	X509_free(x);
	if (!pkey)
		goto out;

	RAND_bytes(challenge, sizeof(challenge));


	rc = tpm2_create(&tssContext, dir);
	if (rc)
		goto out;

	rc = tpm2_load_srk(tssContext, &eksign, auth, &pubeksign,
			   TPM_RH_ENDORSEMENT, TPM2_SIGNING);
	if (rc)
		goto out;

	tpm2_ObjectPublic_GetName(&eksignname, &pubeksign.publicArea);

	if (namefile) {
		bin2hex(hexname, (unsigned char *)eksignname.name,
			eksignname.size);
		rc = verify_hexname(namefile, hexname);
		if (rc) {
			fprintf(stderr, "Error: signing EK failed name verification\n");
			goto out_free_eksign;
		}
	}

	/* run MakeCredential using just openssl */
	memcpy(digest.buffer, challenge, sizeof(challenge));
	digest.size = sizeof(challenge);
	size = digest.size + 2;	/* size of marshalled digest */
	private.size = size + integrity_skip;
	buf = &private.buffer[integrity_skip];
	TSS_TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&digest, &written,
				 &buf, &size);
	rc = tpm2_hmacwrap(pkey, &eksignname, "IDENTITY", &private, &enc_secret);
	if (rc)
		goto out_free_eksign;

	rc = load_ek(tssContext, &ek, &high, auth, pkey);
	if (rc)
		goto out_free_eksign;

	/* now we have the EK, we can only use it with a policy */

	rc = tpm2_get_session_handle(tssContext, &policy, 0, TPM_SE_POLICY,
				     TPM_ALG_SHA256);
	if (rc)
		goto out_free_ek;

	/*
	 * two different policies but amounting to the same thing
	 *
	 * low is policy A which is PolicySecret on the endorsement
	 * hierarchy with a zero size policyRef.
	 *
	 * High is the PolicyOR of policy A (which we should satisfy)
	 * and policyC (which we don't bother with because it's not
	 * supported by all TPMs).
	 */
	digest.size = 0;	/* empty policyRef */
	rc = tpm2_PolicySecret(tssContext, TPM_RH_ENDORSEMENT, policy,
			       &digest, auth);
	if (rc) {
		tpm2_error(rc, "tpm2_PolicySecret");
		tpm2_FlushContext(tssContext, policy);
		goto out_free_ek;
	}

	if (high) {
		/* high is PolicyOR of PolicyA and PolicyC */
		TPML_DIGEST digests;

		digests.count = 2;
		/* PolicyA = tcgPolicy[0] */
		VAL_T(digests.digests[0], size) = sizeof(tcgPolicy[0]);
		memcpy(VAL_T(digests.digests[0], buffer), tcgPolicy[0],
		       VAL_T(digests.digests[0], size));
		/* PolicyC = tcgPolicy[2] */
		VAL_T(digests.digests[1], size) = sizeof(tcgPolicy[2]);
		memcpy(VAL_T(digests.digests[1], buffer), tcgPolicy[2],
		       VAL_T(digests.digests[1], size));

		rc = tpm2_PolicyOR(tssContext, policy, &digests);
		if (rc) {
			tpm2_error(rc, "tpm2_PolicyOR");
			tpm2_FlushContext(tssContext, policy);
			goto out_free_ek;
		}
	}

	rc = tpm2_ActivateCredential(tssContext, eksign, ek,
				     (ID_OBJECT_2B *)&private, &enc_secret,
				     &digest, policy);
	if (rc) {
		tpm2_error(rc, "ActivateCredential");
		tpm2_FlushContext(tssContext, policy);
		goto out_free_ek;
	}

	if (memcmp(digest.buffer, challenge, sizeof(challenge)) != 0) {
		fprintf(stderr, "Error: ActivateCredential returned incorrect challenge\n");
		goto out_free_ek;
	}

	rc = 0;
	printf("Attestation of signing EK successful\n");

	if (file)
		rc = write_pubkey(file, &pubeksign.publicArea);

 out_free_ek:
	tpm2_flush_srk(tssContext, ek);
 out_free_eksign:
	tpm2_flush_srk(tssContext, eksign);

	TSS_Delete(tssContext);

 out:
	if (dir)
		rmdir(dir);

	if (ERR_peek_error()) {
		rc = NOT_TPM_ERROR;
		ERR_print_errors_fp(stderr);
	}
	if (rc)
		exit(1);
}

int main(int argc, char **argv)
{
	char *auth = NULL, *pass = NULL;
	char *file = NULL, *namefile = NULL;
	char *handle_str = NULL, *certfile = NULL;
	int ek = 0, outname = 0;
	TPM_HANDLE handle;
	const int max_auth_size = 128;
#define ATTEST (certfile ? 1 : 0)
#define CERTIFY (handle_str ? 1 : 0)


	while (1) {
		int option_index = 0, c;

		c = getopt_long(argc, argv, "ak:EA:C:n:f:o",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			auth = malloc(max_auth_size + 1);
			break;
		case 'k':
			pass = optarg;
			if (strlen(pass) > max_auth_size) {
				fprintf(stderr, "password is too long\n");
				exit(1);
			}
			break;
		case 'E':
			ek = 1;
			break;
		case 'A':
			certfile = optarg;
			break;
		case 'C':
			handle_str = optarg;
			break;
		case 'n':
			namefile = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'o':
			outname = 1;
			break;
		default:
			printf("Unknown option '%c'\n", c);
			usage(argv[0]);
			break;
		}
	}

	if (optind < argc - 1 || ((ek || ATTEST) && optind != argc)) {
		printf("Unexpected additional arguments\n");
		usage(argv[0]);
	}

	if (ek + ATTEST + CERTIFY > 1) {
		fprintf(stderr, "only one of --ek, --attest or --certify may be specified\n");
		exit(1);
	} else if (ek + ATTEST + CERTIFY == 0) {
		fprintf(stderr, "at least one of --ek, --attest or --certify must be specified\n");
		exit(1);
	}

	if (auth) {
		if (pass)
			strcpy(auth, pass);
		else
			EVP_read_pw_string(auth, max_auth_size,
					   "Enter EK hierarchy authority: ", 0);
	}

	if (ek) {
		do_ek(auth, namefile, file);
	} else if (certfile) {
		do_attest(auth, namefile, file, certfile);
	} else if (handle_str) {
		const char *handlename = NULL;

		handle = tpm2_get_parent_ext(handle_str);
		if (!handle) {
			fprintf(stderr, "Invalid handle for certification\n");
			exit(1);
		}

		if (optind == argc - 1)
			handlename = argv[argc - 1];
		do_certify(auth, handle, namefile, file, handlename, outname);
	}
}
