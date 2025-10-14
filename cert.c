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
	if ((cert->key = keypair_generate(cert)) == NULL)
		return 0;

	return 1;
}

static int
cert_set_name(struct cert *cert, struct name *namedat, X509_NAME **out_name)
{
	X509_NAME *name = NULL;

	*out_name = NULL;

	if ((name = X509_NAME_new()) == NULL) {
		cert->errstr = "X509_NAME_new";
		return 0;
	}

	if (namedat->c && !X509_NAME_add_entry_by_NID(name, NID_countryName,
	    V_ASN1_PRINTABLESTRING, (unsigned char *)namedat->c, -1, -1, 0))
		goto err;

	if (namedat->o && !X509_NAME_add_entry_by_NID(name, NID_organizationName,
	    V_ASN1_PRINTABLESTRING, (unsigned char *)namedat->o, -1, -1, 0))
		goto err;

	if (namedat->ou && !X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName,
	    V_ASN1_PRINTABLESTRING, (unsigned char *)namedat->ou, -1, -1, 0))
		goto err;

	if (namedat->dnq && !X509_NAME_add_entry_by_NID(name, NID_distinguishedName,
	    V_ASN1_PRINTABLESTRING, (unsigned char *)namedat->dnq, -1, -1, 0))
		goto err;

	if (namedat->st && !X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName,
	    V_ASN1_PRINTABLESTRING, (unsigned char *)namedat->st, -1, -1, 0))
		goto err;

	if (namedat->cn && !X509_NAME_add_entry_by_NID(name, NID_commonName,
	    V_ASN1_PRINTABLESTRING, (unsigned char *)namedat->cn, -1, -1, 0))
		goto err;

	if (namedat->ser && !X509_NAME_add_entry_by_NID(name, NID_serialNumber,
	    V_ASN1_PRINTABLESTRING, (unsigned char *)namedat->ser, -1, -1, 0))
		goto err;

	*out_name = name;

	return 1;
 err:
	cert->errstr = "X509_NAME_add_entry_by_NID";
	X509_NAME_free(name);

	return 0;
}

static int
cert_set_version(struct cert *cert)
{
	if (!X509_set_version(cert->x509, X509_VERSION_3)) {
		cert->errstr = "X509_set_version";

		return 0;
	}

	return 1;
}

static int
cert_set_serial_number_rand(struct cert *cert)
{
	BIGNUM *bn;
	ASN1_INTEGER *serialNumber;

	if ((bn = BN_new()) == NULL) {
		cert->errstr = "BN_new";
		return 0;
	}

	do {
		/* Choose a random number in [1..2^159 - 1] by default. */
		if (!BN_rand(bn, 159, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
			cert->errstr = "BN_rand";
			return 0;
		}
	} while (BN_is_zero(bn));

	if ((serialNumber = BN_to_ASN1_INTEGER(bn, NULL)) == NULL) {
		cert->errstr = "BN_to_ASN1_INTEGER";
		return 0;
	}

	if (!X509_set_serialNumber(cert->x509, serialNumber)) {
		cert->errstr = "X509_set_serialNumber";
		return 0;
	}

	BN_free(bn);
	ASN1_INTEGER_free(serialNumber);

	return 1;
}

static int
cert_set_serial_number(struct cert *cert)
{
	ASN1_INTEGER *serialNumber;
	int ret = 0;

	if (cert->config->serial == 0)
		return cert_set_serial_number_rand(cert);

	if ((serialNumber = ASN1_INTEGER_new()) == NULL) {
		cert->errstr = "ASN1_INTEGER_set_uint64";
		return 0;
	}

	if (!ASN1_INTEGER_set_uint64(serialNumber, cert->config->serial)) {
		cert->errstr = "ASN1_INTEGER_set_uint64";
		goto out;
	}

	if (!X509_set_serialNumber(cert->x509, serialNumber)) {
		cert->errstr = "X509_set_serialNumber";
		goto out;
	}

	ret = 1;
 out:
	ASN1_INTEGER_free(serialNumber);
	return ret;
}

static int
cert_set_issuer(struct cert *cert)
{
	X509_NAME *issuer;

	if (cert->config->issuer.c == NULL &&
	    cert->config->issuer.o == NULL &&
	    cert->config->issuer.ou == NULL &&
	    cert->config->issuer.dnq == NULL &&
	    cert->config->issuer.st == NULL &&
	    cert->config->issuer.cn == NULL &&
	    cert->config->issuer.ser == NULL)
		cert->config->issuer.cn = strdup("localhost");

	if (!cert_set_name(cert, &cert->config->issuer, &issuer))
		return 0;

	if (!X509_set_issuer_name(cert->x509, issuer)) {
		cert->errstr = "X509_set_issuer_name";
		X509_NAME_free(issuer);
		return 0;
	}

	X509_NAME_free(issuer);

	return 1;
}

static int
cert_set_subject(struct cert *cert)
{
	X509_NAME *subject;

	if (cert->config->subject.c == NULL &&
	    cert->config->subject.o == NULL &&
	    cert->config->subject.ou == NULL &&
	    cert->config->subject.dnq == NULL &&
	    cert->config->subject.st == NULL &&
	    cert->config->subject.cn == NULL &&
	    cert->config->subject.ser == NULL)
		cert->config->subject.cn = strdup("localhost");

	if (!cert_set_name(cert, &cert->config->subject, &subject))
		return 0;

	if (!X509_set_subject_name(cert->x509, subject)) {
		cert->errstr = "X509_set_subject_name";
		X509_NAME_free(subject);
		return 0;
	}

	X509_NAME_free(subject);

	return 1;
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

	return -1;
}

static int
cert_set_validity(struct cert *cert)
{
	ASN1_TIME *notBefore, *notAfter;
	int days = 0;

	if (cert->config->notBefore == 0)
		cert->config->notBefore = time(NULL);

	if (cert->config->notAfter == 0) {
		cert->config->notAfter = cert->config->notBefore;
		days = cert_kind_to_days(cert->config->kind);
		if (days == -1) {
			cert->errstr = "no default days";
			return 0;
		}
	}

	notBefore = X509_time_adj_ex(NULL, 0, 0, &cert->config->notBefore);
	if (notBefore == NULL) {
		cert->errstr = "X509_time_adj_ex";
		return 0;
	}
	notAfter = X509_time_adj_ex(NULL, days, 0, &cert->config->notAfter);
	if (notAfter == NULL) {
		cert->errstr = "X509_time_adj_ex";
		return 0;
	}

	if (!X509_set1_notBefore(cert->x509, notBefore)) {
		cert->errstr = "X509_set1_notBefore";
		return 0;
	}
	if (!X509_set1_notAfter(cert->x509, notAfter)) {
		cert->errstr = "X509_set1_notAfter";
		return 0;
	}

	ASN1_TIME_free(notBefore);
	ASN1_TIME_free(notAfter);

	return 1;
}

static int
cert_set_subject_public_key_info(struct cert *cert, EVP_PKEY *subject_key)
{
	if (!X509_set_pubkey(cert->x509, subject_key)) {
		cert->errstr = "X509_set_pubkey";
		return 0;
	}

	return 1;
}

static int
cert_add_extension(struct cert *cert, X509_EXTENSION *ext)
{
	if (!X509_add_ext(cert->x509, ext, -1)) {
		cert->errstr = "X509_add_ext";
		return 0;
	}

	X509_EXTENSION_free(ext);

	return 1;
}

static int
cert_set_basic_constraints(struct cert *cert)
{
	X509_EXTENSION *ext;

	/* MUST NOT be present in end entity certs. */
	if (cert->config->kind == CERT_KIND_EE)
		return 1;

	/*
	 * Basic Constraints MUST be present in CA certs.
	 * cA Boolean MUST be set, pathLen MUST NOT be present.
	 */
	if ((ext = ext_basic_constraints_new(1)) == NULL) {
		cert->errstr = "ext_data_basic_constraints_new";
		return 0;
	}

	if (!cert_add_extension(cert, ext))
		return 0;

	return 1;
}

static int
cert_set_subject_key_identifier(struct cert *cert, EVP_PKEY *subject_key)
{
	X509_EXTENSION *ext;

	if ((ext = ext_subject_key_identifier_new(subject_key)) == NULL) {
		cert->errstr = "ext_subject_key_identifier_new";
		return 0;
	}

	if (!cert_add_extension(cert, ext))
		return 0;

	return 1;
}

static int
cert_set_authority_key_identifier(struct cert *cert, EVP_PKEY *issuer_key)
{
	X509_EXTENSION *ext;

	/*
	 * The AKI MUST appear in all resource certificates, except self-signed
	 * CA certs. Self-signed certs MAY include it, so we include it. The
	 * Key Identifier MUST be present; MUST omit authorityCertIssuer and
	 * authorityCertSerialNumber.
	 */
	if ((ext = ext_authority_key_identifier_new(issuer_key)) == NULL) {
		cert->errstr = "ext_authority_key_identifier_new";
		return 0;
	}

	if (!cert_add_extension(cert, ext))
		return 0;

	return 1;
}

static int
cert_set_key_usage(struct cert *cert)
{
	X509_EXTENSION *ext;
	uint32_t ku_flags;

	/*
	 * EE certs, exactly digitalSignature is set to true.
	 * CA certs, exactly keyCertSign and cRLSign are set to true.
	 */
	if (cert->config->kind == CERT_KIND_EE)
		ku_flags = X509v3_KU_DIGITAL_SIGNATURE;
	else
		ku_flags = X509v3_KU_KEY_CERT_SIGN | X509v3_KU_CRL_SIGN;

	if ((ext = ext_key_usage_new(ku_flags)) == NULL) {
		cert->errstr = "ext_key_usage";
		return 0;
	}

	if (!cert_add_extension(cert, ext))
		return 0;

	return 1;
}

static int
cert_set_extended_key_usage(struct cert *cert)
{
	return 1;
}

static int
cert_set_crl_distribution_points(struct cert *cert)
{
	X509_EXTENSION *ext;

	if (cert->config->crl_len == 0)
		return 1;

	/* In a self-signed certificate, this extension MUST be omitted. */
	if (cert->config->kind == CERT_KIND_TA)
		return 1;

	/*
	 * Contains a single rsync:// URI in the distributionPoint's fullName
	 * field. No CRLIssuer, no Reasons, no nameRelativeToCRLIssuer.
	 */

	if ((ext = ext_crl_distribution_points_new(cert->config->crl_list,
	    cert->config->crl_len)) == NULL) {
		cert->errstr = "ext_crl_distribution_points_new";
		return 0;
	}

	if (!cert_add_extension(cert, ext))
		return 0;

	return 1;
}

static int
cert_set_authority_info_access(struct cert *cert)
{
	X509_EXTENSION *ext;
	const struct access_method am = {
		.nid = NID_ad_ca_issuers,
		.uri = "rsync://foo.baz/whee",
	};

	/* In a self-signed certificate, this extension MUST be omitted. */
	if (cert->config->kind == CERT_KIND_TA)
		return 1;

	if ((ext = ext_authority_info_access_new(&am)) == NULL) {
		cert->errstr = "ext_authority_info_access_new";
		return 0;
	}

	if (!cert_add_extension(cert, ext))
		return 0;

	return 1;
}

static int
cert_set_subject_info_access(struct cert *cert)
{
	X509_EXTENSION *ext;
	const struct access_method *ams;
	size_t nams;

	if (cert->config->kind == CERT_KIND_EE) {
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

	if ((ext = ext_subject_info_access_new(ams, nams)) == NULL) {
		cert->errstr = "ext_subject_info_access_new";
		return 0;
	}

	if (!cert_add_extension(cert, ext))
		return 0;

	return 1;
}

static int
cert_set_certificate_policies(struct cert *cert)
{
	X509_EXTENSION *ext;

	if ((ext = ext_certificate_policies_new(NID_ipAddr_asNumber,
	    cert->config->cps)) == NULL) {
		cert->errstr = "ext_certificate_policies_new";
		return 0;
	}

	if (!cert_add_extension(cert, ext))
		return 0;

	return 1;
}

static int
cert_set_extensions(struct cert *cert, EVP_PKEY *subject_key,
    EVP_PKEY *issuer_key)
{
	if (!cert_set_basic_constraints(cert))
		return 0;
	if (!cert_set_subject_key_identifier(cert, subject_key))
		return 0;
	if (!cert_set_authority_key_identifier(cert, issuer_key))
		return 0;
	if (!cert_set_key_usage(cert))
		return 0;
	if (!cert_set_extended_key_usage(cert))
		return 0;
	if (!cert_set_crl_distribution_points(cert))
		return 0;
	if (!cert_set_authority_info_access(cert))
		return 0;
	if (!cert_set_subject_info_access(cert))
		return 0;
	if (!cert_set_certificate_policies(cert))
		return 0;

	return 1;
}

static int
cert_sign(struct cert *cert, EVP_PKEY *issuer_key)
{
	if (!X509_sign(cert->x509, issuer_key, EVP_sha256())) {
		cert->errstr = "X509_digest";
		return 0;
	}

	return 1;
}

int
cert_from_subject_and_issuer_key(struct cert *cert, EVP_PKEY *subject_key,
    EVP_PKEY *issuer_key)
{
	if (!cert_set_version(cert))
		return 0;
	if (!cert_set_serial_number(cert))
		return 0;

	/* Signature Algorithm will be set when we sign. */
	if (!cert_set_issuer(cert))
		return 0;
	if (!cert_set_subject(cert))
		return 0;
	if (!cert_set_validity(cert))
		return 0;
	if (!cert_set_subject_public_key_info(cert, subject_key))
		return 0;
	if (!cert_set_extensions(cert, subject_key, issuer_key))
		return 0;

	if (!cert_sign(cert, issuer_key))
		return 0;

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

	memset(config, 0, sizeof *config);

	config->keytype = KEYPAIR_RSA;
	config->kind = CERT_KIND_EE;

	return config;
}

void
cert_config_free(struct cert_config *config)
{
	while (config->crl_len--)
		free(config->crl_list[config->crl_len]);

	free(config->cps);
	free(config->crl_list);

	free(config->issuer.c);
	free(config->issuer.o);
	free(config->issuer.ou);
	free(config->issuer.dnq);
	free(config->issuer.st);
	free(config->issuer.cn);
	free(config->issuer.ser);

	free(config->subject.c);
	free(config->subject.o);
	free(config->subject.ou);
	free(config->subject.dnq);
	free(config->subject.st);
	free(config->subject.cn);
	free(config->subject.ser);

	free(config);
}

/*
 * Configure Certificate Type
 */

void
cert_config_set_ee(struct cert_config *config)
{
	config->kind = CERT_KIND_EE;
}

void
cert_config_set_ca(struct cert_config *config)
{
	config->kind = CERT_KIND_CA;
}

void
cert_config_set_ta(struct cert_config *config)
{
	config->kind = CERT_KIND_TA;
}

/*
 * Configure Issuer Names
 */

void
cert_config_issuer_c(struct cert_config *config, const char *c)
{
	config->issuer.c = strdup(c);
}

void
cert_config_issuer_o(struct cert_config *config, const char *o)
{
	config->issuer.o = strdup(o);
}

void
cert_config_issuer_ou(struct cert_config *config, const char *ou)
{
	config->issuer.ou = strdup(ou);
}

void
cert_config_issuer_dnq(struct cert_config *config, const char *dnq)
{
	config->issuer.dnq = strdup(dnq);
}

void
cert_config_issuer_st(struct cert_config *config, const char *st)
{
	config->issuer.st = strdup(st);
}

void
cert_config_issuer_cn(struct cert_config *config, const char *cn)
{
	config->issuer.cn = strdup(cn);
}

void
cert_config_issuer_ser(struct cert_config *config, const char *ser)
{
	config->issuer.ser = strdup(ser);
}

/*
 * Configure Subject Names
 */

void
cert_config_subject_c(struct cert_config *config, const char *c)
{
	config->subject.c = strdup(c);
}

void
cert_config_subject_o(struct cert_config *config, const char *o)
{
	config->subject.o = strdup(o);
}

void
cert_config_subject_ou(struct cert_config *config, const char *ou)
{
	config->subject.ou = strdup(ou);
}

void
cert_config_subject_dnq(struct cert_config *config, const char *dnq)
{
	config->subject.dnq = strdup(dnq);
}

void
cert_config_subject_st(struct cert_config *config, const char *st)
{
	config->subject.st = strdup(st);
}

void
cert_config_subject_cn(struct cert_config *config, const char *cn)
{
	config->subject.cn = strdup(cn);
}

void
cert_config_subject_ser(struct cert_config *config, const char *ser)
{
	config->subject.ser = strdup(ser);
}

void
cert_config_set_cps(struct cert_config *config, const char *cps)
{
	config->cps = strdup(cps);
}

int
cert_config_add_crl_uri(struct cert_config *config, const char *uri)
{
	char **old = config->crl_list;

	config->crl_len++;
	config->crl_list = reallocarray(config->crl_list,
	    sizeof config->crl_list[0], config->crl_len);
	if (config->crl_list == NULL) {
		free(old);
		return 0;
	}

	if ((config->crl_list[config->crl_len - 1] = strdup(uri)) == NULL)
		return 0;

	return 1;
}

void
cert_config_notBefore(struct cert_config *config, time_t notBefore)
{
	config->notBefore = notBefore;
}

void
cert_config_notAfter(struct cert_config *config, time_t notAfter)
{
	config->notAfter = notAfter;
}

void
cert_config_serial(struct cert_config *config, uint64_t serial)
{
	config->serial = serial;
}

struct cert *
cert_new(void)
{
	struct cert *cert;

	cert = malloc(sizeof *cert);
	if (cert == NULL)
		return NULL;

	if ((cert->x509 = X509_new()) == NULL) {
		free(cert);
		return NULL;
	}

	return cert;
}

void
cert_free(struct cert *cert)
{
	X509_free(cert->x509);

	free(cert);
}

int
cert_create(struct cert *cert, struct cert_config *config)
{
	if (cert == NULL)
		return 0;

	if (config == NULL) {
		cert->errstr = "certificate configuration is NULL";
		return 0;
	}

	cert->config = config;

	if (!cert_generate_keys(cert))
		return 0;

	cert_from_subject_and_issuer_key(cert, cert->key, cert->key);

	return 1;
}
