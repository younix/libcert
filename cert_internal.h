/*
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

#ifndef CERT_INTERNAL_H
#define CERT_INTERNAL_H

#include <openssl/x509.h>
#include "openssl-compat.h"	/* IWYU pragma: export */

struct access_method {
	int nid;
	const char *uri;
};

/*
 * Create X.509v3 extensions.
 *
 * Pass the relevant info to be inserted into an X509_EXTENSION object that
 * needs to be freed with X509_EXTENSION_free(). No arguments are modified and
 * ownership is never taken. The API is not const correct due to limitations
 * of the OpenSSL API - e.g., it needs to fiddle with the EVP_PKEY's refcount.
 *
 * More detailed documentation is above the individual implementations.
 */

X509_EXTENSION	*ext_basic_constraints_new(int ca);
X509_EXTENSION	*ext_subject_key_identifier_new(EVP_PKEY *subject_key);
X509_EXTENSION	*ext_authority_key_identifier_new(EVP_PKEY *issuer_key);
X509_EXTENSION	*ext_key_usage_new(uint32_t flags);
X509_EXTENSION	*ext_extended_key_usage_new(uint64_t flags);
X509_EXTENSION	*ext_certificate_policies_new(int nid, const char *cpsuri);
X509_EXTENSION	*ext_crl_distribution_points_new(char **uris, size_t nuris);
X509_EXTENSION	*ext_authority_info_access_new(const struct access_method *am);
X509_EXTENSION	*ext_subject_info_access_new(const struct access_method ams[],
		    size_t nams);

/*
 * RFC 7299, Section 3.6 - SMI security for PKIX Extended Key Purpose
 *
 * Parent OID: 1.3.6.1.5.5.7.3
 *
 */

#define EKU_SERVER_AUTH		(1ULL << 1)	/* id-kp-serverAuth */
#define EKU_CLIENT_AUTH		(1ULL << 2)	/* id-kp-clientAuth */
#define EKU_CODE_SIGNING	(1ULL << 3)	/* id-kp-codeSigning */
#define EKU_EMAIL_PROTECTION	(1ULL << 4)	/* id-kp-emailProtection */
#define EKU_TIME_STAMPING	(1ULL << 8)	/* id-kp-timeStamping */
#define EKU_OCSP_SIGNING	(1ULL << 9)	/* id-kp-OCSPSigning */
#define EKU_DVCS		(1ULL << 10)	/* id-kp-dvcs */
/* RFC 5280, section 4.2.1.12 */
#define EKU_ANY_EXT_KEY_USAGE	(1ULL << 63)	/* anyExtKeyUsage */

int key_identifier(EVP_PKEY *pkey, unsigned char *md, unsigned int *md_len);

enum keypair {
	KEYPAIR_RSA,
	KEYPAIR_ECDSA,
};

enum cert_kind {
	CERT_KIND_EE,	/* End Entity */
	CERT_KIND_CA,	/* Certificate Authority */
	CERT_KIND_TA,	/* Trust Anchor */
};

struct name {
	char	*c;	/* country */
	char	*o;	/* organization */
	char	*ou;	/* organizational unit */
	char	*dnq;	/* distinguished name qualifier */
	char	*st;	/* state or province name */
	char	*cn;	/* common name */
	char	*ser;	/* serial number */
};

struct cert_config {
	enum keypair	  keytype;
	enum cert_kind	  kind;
	uint64_t	  serial;
	time_t		  notBefore;
	time_t		  notAfter;
	size_t		  crl_len;
	char		**crl_list;	/* Certificate Revocation List */
	struct name	  issuer;
	struct name	  subject;
	char		 *cps;		/* Certification Practice Statement*/
};

struct cert {
	struct cert_config	*config;
	EVP_PKEY		*key;
	X509			*x509;

	const char		*errstr;
};

EVP_PKEY *keypair_generate(struct cert *);
EVP_PKEY *keypair_extract_public(struct cert *);

#endif
