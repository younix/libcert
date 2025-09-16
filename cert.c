/*
 * Copyright (c) 2024 Theo Buehler <tb@openbsd.org>
 * Copyright (c) 2025 Jan Klemkow <j.klemkow@wemelug.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "extern.h"
#include "cert.h"

/*
 * Inputs:
 *
 *	issuer
 *	subject
 *	certificate type (EE/CA/TA)
 *	public key
 *	signing key
 *
 *	serial number
 *	CRL distribution point URI
 *	AIA caIssuers access method
 *	SIA
 *	optional CPS
 */

static int
cert_generate_keys(struct cert *cert)
{
	if ((cert->key = keypair_generate(cert->config->keytype)) == NULL) {
		cert->errstr = "keypair_generate";
		return 0;
	}

	return 1;
}

static void
cert_set_common_name(EVP_PKEY *pkey, X509_NAME **out_name)
{
	X509_NAME *name = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len = EVP_MAX_MD_SIZE;

	*out_name = NULL;

	if (!key_identifier(pkey, md, &md_len))
		errx(1, "%s: key_identifier", __func__);

	if ((name = X509_NAME_new()) == NULL)
		errx(1, "X509_NAME_new");

	if (!X509_NAME_add_entry_by_NID(name, NID_commonName,
	    V_ASN1_PRINTABLESTRING, (unsigned char *)"localhost", -1, -1, 0))
		errx(1, "X509_NAME_add_entry_by_NID");

	*out_name = name;
}

static void
cert_issuer_from_key(EVP_PKEY *pkey, X509_NAME **out_issuer)
{
	cert_set_common_name(pkey, out_issuer);
}

static void
cert_subject_from_key(EVP_PKEY *pkey, X509_NAME **out_subject)
{
	cert_set_common_name(pkey, out_subject);
}

int
cert_new(struct cert *cert)
{
	if ((cert->x509 = X509_new()) == NULL) {
		cert->errstr = "X509_new";
		return 0;
	}

	return 1;
}

static void
cert_set_version(X509 *cert)
{
	if (!X509_set_version(cert, X509_VERSION_3))
		errx(1, "X509_set_version");
}

static void
cert_set_serial_number(X509 *cert)
{
	BIGNUM *bn;
	ASN1_INTEGER *serialNumber;

	/* XXX - choose a random number in [1..2^159 - 1] for now. */
	if ((bn = BN_new()) == NULL)
		errx(1, "BN_new");
	do {
		if (!BN_rand(bn, 159, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
			errx(1, "BN_rand");
	} while (BN_is_zero(bn));

	if ((serialNumber = BN_to_ASN1_INTEGER(bn, NULL)) == NULL)
		errx(1, "BN_to_ASN1_INTEGER");

	if (!X509_set_serialNumber(cert, serialNumber))
		errx(1, "X509_set_serialNumber");

	BN_free(bn);
	ASN1_INTEGER_free(serialNumber);
}

static void
cert_set_issuer(X509 *cert, EVP_PKEY *issuer_key)
{
	X509_NAME *issuer;

	cert_issuer_from_key(issuer_key, &issuer);
	if (!X509_set_issuer_name(cert, issuer))
		errx(1, "X509_set_issuer_name");
	X509_NAME_free(issuer);
}

static void
cert_set_subject(X509 *cert, EVP_PKEY *subject_key)
{
	X509_NAME *subject;

	cert_subject_from_key(subject_key, &subject);
	if (!X509_set_subject_name(cert, subject))
		errx(1, "X509_set_subject_name");
	X509_NAME_free(subject);
}

static int
cert_kind_to_days(enum cert_kind kind)
{
	switch (kind) {
	case CERT_KIND_EE:
		return 30;
	case CERT_KIND_CA:
		return 365;
	case CERT_KIND_TA:
		return 5 * 365;
	}
	errx(1, "%s: unreachable", __func__);
}

static void
cert_set_validity(X509 *cert, enum cert_kind kind)
{
	ASN1_TIME *notBefore, *notAfter;
	int days = cert_kind_to_days(kind);
	time_t now = time(NULL); /* XXX - make this a global. */

	if ((notBefore = X509_time_adj_ex(NULL, 0, 0, &now)) == NULL)
		errx(1, "X509_time_adj_ex");
	if ((notAfter = X509_time_adj_ex(NULL, days, 0, &now)) == NULL)
		errx(1, "X509_time_adj_ex");

	if (!X509_set1_notBefore(cert, notBefore))
		errx(1, "X509_set1_notBefore");
	if (!X509_set1_notAfter(cert, notAfter))
		errx(1, "X509_set1_notAfter");

	ASN1_TIME_free(notBefore);
	ASN1_TIME_free(notAfter);
}

static void
cert_set_subject_public_key_info(X509 *cert, EVP_PKEY *subject_key)
{
	if (!X509_set_pubkey(cert, subject_key))
		errx(1, "X509_set_pubkey");
}

static void
cert_add_extension(X509 *cert, X509_EXTENSION *ext)
{
	if (!X509_add_ext(cert, ext, -1))
		errx(1, "X509_add_ext");

	X509_EXTENSION_free(ext);
}

static void
cert_set_basic_constraints(X509 *cert, enum cert_kind kind)
{
	X509_EXTENSION *ext;

	/* MUST NOT be present in end entity certs. */
	if (kind == CERT_KIND_EE)
		return;

	/*
	 * Basic Constraints MUST be present in CA certs.
	 * cA Boolean MUST be set, pathLen MUST NOT be present.
	 */
	if ((ext = ext_basic_constraints_new(1)) == NULL)
		errx(1, "ext_data_basic_constraints_new");

	cert_add_extension(cert, ext);
	ext = NULL;
}

static void
cert_set_subject_key_identifier(X509 *cert, EVP_PKEY *subject_key)
{
	X509_EXTENSION *ext;

	if ((ext = ext_subject_key_identifier_new(subject_key)) == NULL)
		errx(1, "ext_subject_key_identifier_new");

	cert_add_extension(cert, ext);
	ext = NULL;
}

static void
cert_set_authority_key_identifier(X509 *cert, EVP_PKEY *issuer_key)
{
	X509_EXTENSION *ext;

	/*
	 * The AKI MUST appear in all resource certificates, except self-signed
	 * CA certs. Self-signed certs MAY include it, so we include it. The
	 * Key Identifier MUST be present; MUST omit authorityCertIssuer and
	 * authorityCertSerialNumber.
	 */
	if ((ext = ext_authority_key_identifier_new(issuer_key)) == NULL)
		errx(1, "ext_authority_key_identifier_new");

	cert_add_extension(cert, ext);
	ext = NULL;
}

static void
cert_set_key_usage(X509 *cert, enum cert_kind kind)
{
	X509_EXTENSION *ext;
	uint32_t ku_flags;

	/*
	 * EE certs, exactly digitalSignature is set to true.
	 * CA certs, exactly keyCertSign and cRLSign are set to true.
	 */
	if (kind == CERT_KIND_EE)
		ku_flags = X509v3_KU_DIGITAL_SIGNATURE;
	else
		ku_flags = X509v3_KU_KEY_CERT_SIGN | X509v3_KU_CRL_SIGN;

	if ((ext = ext_key_usage_new(ku_flags)) == NULL)
		errx(1, "ext_key_usage");

	cert_add_extension(cert, ext);
	ext = NULL;
}

static void
cert_set_extended_key_usage(X509 *cert, enum cert_kind kind)
{
}

/* XXX - make this configurable. */
static void
cert_set_crl_distribution_points(X509 *cert, enum cert_kind kind)
{
	X509_EXTENSION *ext;
	const char *uris[] = {
		"rsync://example.com/my.crl",
		"https://example.com/my.crl",
	};

	/* In a self-signed certificate, this extension MUST be omitted. */
	if (kind == CERT_KIND_TA)
		return;

	/*
	 * Contains a single rsync:// URI in the distributionPoint's fullName
	 * field. No CRLIssuer, no Reasons, no nameRelativeToCRLIssuer.
	 */

	if ((ext = ext_crl_distribution_points_new(uris, 2)) == NULL)
		errx(1, "ext_crl_distribution_points_new");

	cert_add_extension(cert, ext);
	ext = NULL;
}

static void
cert_set_authority_info_access(X509 *cert, enum cert_kind kind)
{
	X509_EXTENSION *ext;
	const struct access_method am = {
		.nid = NID_ad_ca_issuers,
		.uri = "rsync://foo.baz/whee",
	};

	/* In a self-signed certificate, this extension MUST be omitted. */
	if (kind == CERT_KIND_TA)
		return;

	if ((ext = ext_authority_info_access_new(&am)) == NULL)
		errx(1, "ext_authority_info_access_new");

	cert_add_extension(cert, ext);
	ext = NULL;
}

static void
cert_set_subject_info_access(X509 *cert, enum cert_kind kind)
{
	X509_EXTENSION *ext;
	const struct access_method *ams;
	size_t nams;

	if (kind == CERT_KIND_EE) {
		static const struct access_method ee_am = {
			.nid = NID_signedObject,
			.uri = "rsync://foo.myca.net/ca",
		};

		ams = &ee_am;
		nams = 1;
	} else {
		static const struct access_method ca_ams[] = {
			{
				.nid = NID_caRepository,
				.uri = "rsync://foo.myca.net/ca",
			},
			{
				.nid = NID_rpkiManifest,
				.uri = "rsync://foo.myca.net/ca/my.mft",
			},
			{
				.nid = NID_rpkiNotify,
				.uri = "https://foo.myca.net/rrdp/notify.xml",
			},
		};

		ams = ca_ams;
		nams = sizeof(ca_ams) / sizeof(ca_ams[0]);
	}

	if ((ext = ext_subject_info_access_new(ams, nams)) == NULL)
		errx(1, "ext_subject_info_access_new");

	cert_add_extension(cert, ext);
	ext = NULL;
}

static void
cert_set_certificate_policies(X509 *cert)
{
	X509_EXTENSION *ext;

	if ((ext = ext_certificate_policies_new(NID_ipAddr_asNumber,
	    "https://example.com/CPS.pdf")) == NULL)
		errx(1, "ext_certificate_policies_new");

	cert_add_extension(cert, ext);
	ext = NULL;
}

static void
cert_set_extensions(X509 *cert, enum cert_kind kind, EVP_PKEY *subject_key,
    EVP_PKEY *issuer_key)
{
	cert_set_basic_constraints(cert, kind);
	cert_set_subject_key_identifier(cert, subject_key);
	cert_set_authority_key_identifier(cert, issuer_key);
	cert_set_key_usage(cert, kind);
	cert_set_extended_key_usage(cert, kind);
	cert_set_crl_distribution_points(cert, kind);
	cert_set_authority_info_access(cert, kind);
	cert_set_subject_info_access(cert, kind);
	cert_set_certificate_policies(cert);
}

static void
cert_sign(X509 *cert, EVP_PKEY *issuer_key)
{
	if (!X509_sign(cert, issuer_key, EVP_sha256()))
		errx(1, "X509_digest");
}

int
cert_from_subject_and_issuer_key(struct cert *cert, EVP_PKEY *subject_key, EVP_PKEY *issuer_key,
    enum cert_kind kind)
{
	if (cert_new(cert) == 0)
		return 0;

	cert_set_version(cert->x509);
	cert_set_serial_number(cert->x509);
	/* Signature Algorithm will be set when we sign. */
	cert_set_issuer(cert->x509, issuer_key);
	cert_set_subject(cert->x509, subject_key);
	cert_set_validity(cert->x509, kind);
	cert_set_subject_public_key_info(cert->x509, subject_key);
	cert_set_extensions(cert->x509, kind, subject_key, issuer_key);

	cert_sign(cert->x509, issuer_key);

	return 1;
}

/* Get memory pointer of x509 object. */
int
cert_crt_data(struct cert *cert, uint8_t **data, size_t *size)
{
	BIO	*bio;
	BUF_MEM	 mem;

	memset(&mem, 0, sizeof mem);
	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		cert->errstr = "BIO_new";
		return 0;
	}

	if (BIO_set_mem_buf(bio, &mem, BIO_NOCLOSE) <= 0) {
		cert->errstr = "BIO_set_mem_buf";
		goto err;
	}

	if (PEM_write_bio_X509(bio, cert->x509) == 0) {
		cert->errstr = "PEM_write_bio_X509";
		goto err;
	}

	if (BIO_free(bio) == 0) {
		cert->errstr = "BIO_free";
		return 0;
	}

	*data = (uint8_t *)mem.data;
	*size = mem.length;

	return 1;
 err:
	BIO_free(bio);
	return 0;
}

/* Get memory pointer of pkey object. */
int
cert_key_data(struct cert *cert, uint8_t **data, size_t *size)
{
	BIO	*bio;
	BUF_MEM	 mem;

	memset(&mem, 0, sizeof mem);
	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		cert->errstr = "BIO_new";
		return 0;
	}

	if (BIO_set_mem_buf(bio, &mem, BIO_NOCLOSE) <= 0) {
		cert->errstr = "BIO_set_mem_buf";
		goto err;
	}

	if (PEM_write_bio_PrivateKey(bio, cert->key, NULL, NULL, 0, NULL,
	   NULL) == 0) {
		cert->errstr = "PEM_write_bio_PrivateKey";
		return 0;
	}

	if (BIO_free(bio) == 0) {
		cert->errstr = "BIO_free";
		return 0;
	}

	*data = (uint8_t *)mem.data;
	*size = mem.length;

	return 1;
 err:
	BIO_free(bio);
	return 0;
}

struct cert_config *
cert_config_new(void)
{
	struct cert_config *config;

	config = malloc(sizeof *config);
	if (config == NULL)
		return NULL;

	config->keytype = KEYPAIR_RSA;

	return config;
}

void
cert_config_free(struct cert_config *config)
{
	free(config);
}

void
cert_free(struct cert *cert)
{
	X509_free(cert->x509);

	free(cert);
}

struct cert *
cert_create(struct cert_config *config)
{
	struct cert *cert;

	if (config == NULL)
		return NULL;

	cert = malloc(sizeof *cert);
	if (cert == NULL)
		return NULL;

	cert->config = config;

	if (!cert_generate_keys(cert))
		errx(1, "cert_generate_keys");

	cert_from_subject_and_issuer_key(cert, cert->key, cert->key,
	    CERT_KIND_EE);

	return cert;
}
