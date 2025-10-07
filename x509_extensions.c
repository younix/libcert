/*
 * Copyright (c) 2024 Theo Buehler <tb@openbsd.org>
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
#include <stddef.h>
#include <stdint.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "cert.h"

/*
 * RFC 5280, section 4.2.1.9
 */

static BASIC_CONSTRAINTS *
ext_data_basic_constraints_new(int ca)
{
	BASIC_CONSTRAINTS *bc;

	ca = (ca != 0);

	if ((bc = BASIC_CONSTRAINTS_new()) == NULL)
		goto err;

	bc->ca = ca ? ASN1_BOOLEAN_TRUE : ASN1_BOOLEAN_FALSE;
	assert(bc->pathlen == NULL);

	return bc;

 err:
	BASIC_CONSTRAINTS_free(bc);

	return NULL;
}

/*
 * BasicConstraints (critical)
 *
 * CA certs: MUST be present with cA bit set to true
 * EE certs: MUST be absent.
 *
 * If ca != 0 the cA boolean is set to true, otherwise to false (might be needed
 * for CSRs).
 *
 */

X509_EXTENSION *
ext_basic_constraints_new(int ca)
{
	X509_EXTENSION *ext = NULL;
	BASIC_CONSTRAINTS *bc;
	int nid = NID_basic_constraints;

	if ((bc = ext_data_basic_constraints_new(ca)) == NULL)
		goto err;

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_CRITICAL, bc);

 err:
	BASIC_CONSTRAINTS_free(bc);

	return ext;
}

/*
 * Helper for SKI and AKI: return an octet string containing the the SHA-1 of
 * the public key bit string.
 */

static ASN1_OCTET_STRING *
ext_data_key_id_octet_string_new(EVP_PKEY *pkey)
{
	ASN1_OCTET_STRING *ki = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len = EVP_MAX_MD_SIZE;

	if (!key_identifier(pkey, md, &md_len))
		goto err;

	if ((ki = ASN1_OCTET_STRING_new()) == NULL)
		goto err;
	if (!ASN1_STRING_set(ki, md, md_len))
		goto err;

	return ki;

 err:
	ASN1_OCTET_STRING_free(ki);

	return NULL;
}

/*
 * RFC 5280, section 4.2.1.2
 */

static ASN1_OCTET_STRING *
ext_data_subject_key_identifier_new(EVP_PKEY *subject_key)
{
	return ext_data_key_id_octet_string_new(subject_key);
}

/*
 * SubjectKeyIdentifier (non-critical)
 *
 * Contains the SHA-1 of subject_key's public key BIT STRING (excluding tag,
 * length and unused bits).
 *
 */

X509_EXTENSION *
ext_subject_key_identifier_new(EVP_PKEY *subject_key)
{
	X509_EXTENSION *ext = NULL;
	ASN1_OCTET_STRING *ski;
	int nid = NID_subject_key_identifier;

	if ((ski = ext_data_subject_key_identifier_new(subject_key)) == NULL)
		goto err;

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_NONCRITICAL, ski);

 err:
	ASN1_OCTET_STRING_free(ski);

	return ext;
}

/*
 * RFC 5280, section 4.2.1.1
 */

static AUTHORITY_KEYID *
ext_data_authority_key_identifier_new(EVP_PKEY *issuer_key)
{
	AUTHORITY_KEYID *aki = NULL;

	if ((aki = AUTHORITY_KEYID_new()) == NULL)
		goto err;
	assert(aki->keyid == NULL);
	assert(aki->issuer == NULL);
	assert(aki->serial == NULL);

	if ((aki->keyid = ext_data_key_id_octet_string_new(issuer_key)) == NULL)
		goto err;

	return aki;

 err:
	AUTHORITY_KEYID_free(aki);

	return NULL;
}

/*
 * AuthorityKeyIdentifier (non-critical)
 *
 * MUST be present in CA and EE certs. Allowed in TA certs; only NRO does this.
 *
 * The SHA-1 of issuer_key's public key BIT STRING (excluding tag, length and
 * unused bits) is placed in the keyIdentifier. The optional authorityCertIssuer
 * and authorityCertSerialNumber fields are omitted.
 *
 */

X509_EXTENSION *
ext_authority_key_identifier_new(EVP_PKEY *issuer_key)
{
	X509_EXTENSION *ext = NULL;
	AUTHORITY_KEYID *aki;
	int nid = NID_authority_key_identifier;

	if ((aki = ext_data_authority_key_identifier_new(issuer_key)) == NULL)
		goto err;

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_NONCRITICAL, aki);

 err:
	AUTHORITY_KEYID_free(aki);

	return ext;
}

/*
 * RFC 5280, section 4.2.1.3
 */

static const uint32_t ku_mask =
    X509v3_KU_DIGITAL_SIGNATURE |
    X509v3_KU_NON_REPUDIATION |
    X509v3_KU_KEY_ENCIPHERMENT |
    X509v3_KU_DATA_ENCIPHERMENT |
    X509v3_KU_KEY_AGREEMENT |
    X509v3_KU_KEY_CERT_SIGN |
    X509v3_KU_CRL_SIGN |
    X509v3_KU_ENCIPHER_ONLY |
    X509v3_KU_DECIPHER_ONLY;

/*
 * RFC 5280, section 4.2.1.3 - KeyUsage BIT STRING
 *
 * There is no nice way of mapping the X509v3_KU_* flags to the bits
 * that need to be set in the ASN1_BIT_STRING, so we do it by hand.
 */

static const uint32_t ku_flags[] = {
	X509v3_KU_DIGITAL_SIGNATURE,
	X509v3_KU_NON_REPUDIATION,
	X509v3_KU_KEY_ENCIPHERMENT,
	X509v3_KU_DATA_ENCIPHERMENT,
	X509v3_KU_KEY_AGREEMENT,
	X509v3_KU_KEY_CERT_SIGN,
	X509v3_KU_CRL_SIGN,
	X509v3_KU_ENCIPHER_ONLY,
	X509v3_KU_DECIPHER_ONLY,
};

#define N_KU_FLAGS (sizeof(ku_flags) / sizeof(ku_flags[0]))

static ASN1_BIT_STRING *
ext_data_key_usage_new(uint32_t flags)
{
	ASN1_BIT_STRING *ku = NULL;
	size_t bit;

	if ((flags & ku_mask) != flags)
		goto err;

	if ((ku = ASN1_BIT_STRING_new()) == NULL)
		goto err;

	for (bit = 0; bit < N_KU_FLAGS; bit++) {
		if ((flags & ku_flags[bit]) == 0)
			continue;
		if (!ASN1_BIT_STRING_set_bit(ku, bit, 1))
			goto err;
	}

	return ku;

 err:
	ASN1_BIT_STRING_free(ku);

	return NULL;
}

/*
 * KeyUsage (critical)
 *
 * CA certs: keyCertSign | CRLSign
 * EE certs: digitalSignature
 *
 * Pass the appropriate X509v3_KU_* flags ORed together and the corresponding
 * bits will be set in this extension, all others are left unset.
 *
 */

X509_EXTENSION *
ext_key_usage_new(uint32_t flags)
{
	X509_EXTENSION *ext = NULL;
	ASN1_BIT_STRING *ku;
	int nid = NID_key_usage;

	if ((ku = ext_data_key_usage_new(flags)) == NULL)
		goto err;

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_CRITICAL, ku);

 err:
	ASN1_BIT_STRING_free(ku);

	return ext;
}

/*
 * RFC 5280, section 4.2.1.12
 */

static const uint64_t eku_mask =
    EKU_SERVER_AUTH |
    EKU_CLIENT_AUTH |
    EKU_CODE_SIGNING |
    EKU_EMAIL_PROTECTION |
    EKU_TIME_STAMPING |
    EKU_OCSP_SIGNING |
    EKU_DVCS |
    EKU_ANY_EXT_KEY_USAGE;

static const uint64_t eku_flags[] = {
	EKU_SERVER_AUTH,
	EKU_CLIENT_AUTH,
	EKU_CODE_SIGNING,
	EKU_EMAIL_PROTECTION,
	EKU_TIME_STAMPING,
	EKU_OCSP_SIGNING,
	EKU_DVCS,
	EKU_ANY_EXT_KEY_USAGE,
};

#define N_EKU_FLAGS (sizeof(eku_flags) / sizeof(eku_flags[0]))

static int
ext_data_eku_flag2nid(uint64_t flag)
{
	switch (flag) {
	case EKU_SERVER_AUTH:
		return NID_server_auth;
	case EKU_CLIENT_AUTH:
		return NID_client_auth;
	case EKU_CODE_SIGNING:
		return NID_code_sign;
	case EKU_EMAIL_PROTECTION:
		return NID_email_protect;
	case EKU_TIME_STAMPING:
		return NID_time_stamp;
	case EKU_OCSP_SIGNING:
		return NID_OCSP_sign;
	case EKU_DVCS:
		return NID_dvcs;
	case EKU_ANY_EXT_KEY_USAGE:
		return NID_anyExtendedKeyUsage;
	}

	return NID_undef;
}

static STACK_OF(ASN1_OBJECT) *
ext_data_extended_key_usage_new(uint64_t flags)
{
	STACK_OF(ASN1_OBJECT) *eku = NULL;
	ASN1_OBJECT *oid;
	size_t bit;
	int nid;

	if ((flags & eku_mask) != flags)
		goto err;

	if ((eku = sk_ASN1_OBJECT_new_null()) == NULL)
		goto err;

	for (bit = 0; bit < N_EKU_FLAGS; bit++) {
		if ((flags & eku_flags[bit]) == 0)
			continue;

		if ((nid = ext_data_eku_flag2nid(eku_flags[bit])) == NID_undef)
			goto err;
		if ((oid = OBJ_nid2obj(nid)) == NULL)
			goto err;
		if ((sk_ASN1_OBJECT_push(eku, oid)) <= 0)
			goto err;
	}

	return eku;

 err:
	sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);

	return NULL;
}

/*
 * ExtKeyUsage (non-critical)
 *
 * Pass the appropriate EKU_* flags ORed together and the corresponding
 * bits will be set in this extension, all others are left unset.
 *
 * RFC 5280, section 4.2.1.3;
 */

X509_EXTENSION *
ext_extended_key_usage_new(uint64_t flags)
{
	X509_EXTENSION *ext = NULL;
	STACK_OF(ASN1_OBJECT) *eku;
	int nid = NID_ext_key_usage;

	if ((eku = ext_data_extended_key_usage_new(flags)) == NULL)
		goto err;

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_NONCRITICAL, eku);

 err:
	sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);

	return ext;
}

/*
 * RFC 5280, section 4.2.1.13
 */

static ASN1_IA5STRING *
ext_data_ia5string_from_uri(const char *uri)
{
	ASN1_IA5STRING *ia5;

	/* XXX - validate uri */

	if ((ia5 = ASN1_IA5STRING_new()) == NULL)
		goto err;
	if (!ASN1_STRING_set(ia5, uri, -1))
		goto err;

	return ia5;

 err:
	ASN1_IA5STRING_free(ia5);

	return NULL;
}

static GENERAL_NAME *
ext_data_general_name_from_uri(const char *uri)
{
	GENERAL_NAME *name;
	ASN1_IA5STRING *ia5;

	if ((name = GENERAL_NAME_new()) == NULL)
		goto err;
	if ((ia5 = ext_data_ia5string_from_uri(uri)) == NULL)
		goto err;
	GENERAL_NAME_set0_value(name, GEN_URI, ia5);
	ia5 = NULL;

	return name;

 err:
	GENERAL_NAME_free(name);

	return NULL;
}

static GENERAL_NAMES *
ext_data_general_names_from_uris(char **uris, size_t nuris)
{
	GENERAL_NAMES *names;
	GENERAL_NAME *uri = NULL;
	size_t i;

	if ((names = GENERAL_NAMES_new()) == NULL)
		goto err;

	for (i = 0; i < nuris; i++) {
		if ((uri = ext_data_general_name_from_uri(uris[i])) == NULL)
			goto err;
		if ((sk_GENERAL_NAME_push(names, uri)) <= 0)
			goto err;
	}

	return names;

 err:
	GENERAL_NAMES_free(names);
	GENERAL_NAME_free(uri);

	return NULL;
}

static CRL_DIST_POINTS *
ext_data_crl_distribution_points_new(char **uris, size_t nuris)
{
	CRL_DIST_POINTS *crldps = NULL;
	DIST_POINT *distpoint = NULL;
	GENERAL_NAMES *names = NULL;

	/*
	 * XXX - validate uris[]?
	 * Check that there is an rsync:// URI, and that the URI ends in .crl.
	 */
	if (nuris == 0)
		goto err;

	if ((names = ext_data_general_names_from_uris(uris, nuris)) == NULL)
		goto err;

	if ((distpoint = DIST_POINT_new()) == NULL)
		goto err;
	assert(distpoint->distpoint == NULL);
	assert(distpoint->reasons == NULL);
	assert(distpoint->CRLissuer == NULL);
	assert(distpoint->dp_reasons == 0);

	if ((distpoint->distpoint = DIST_POINT_NAME_new()) == NULL)
		goto err;
	assert(distpoint->distpoint->type == -1);
	assert(distpoint->distpoint->name.fullname == NULL);
	assert(distpoint->distpoint->dpname == NULL);

	distpoint->distpoint->type = 0; /* XXX - no #define or enum for this. */
	distpoint->distpoint->name.fullname = names;
	names = NULL;

	if ((crldps = CRL_DIST_POINTS_new()) == NULL)
		goto err;

	if ((sk_DIST_POINT_push(crldps, distpoint)) <= 0)
		goto err;
	distpoint = NULL;

	return crldps;

 err:
	GENERAL_NAMES_free(names);
	DIST_POINT_free(distpoint);
	CRL_DIST_POINTS_free(crldps);

	return NULL;
}

/*
 * cRLDistributionPoints (non-critical)
 *
 * CA/EE certs: MUST be present
 * TA certs: MUST NOT be present
 *
 * Pass in an array of URIs and its size. All URIs must reference the latest
 * .crl and one rsync:// URI must be present. A single DistributionPoint is
 * created whose distributionPoint's fullName contains the sequence of URIs,
 * in particular there is no nameRelativeToCRLIssuer. reasons and cRLIssuer
 * remain unset.
 *
 */

X509_EXTENSION *
ext_crl_distribution_points_new(char **uris, size_t nuris)
{
	X509_EXTENSION *ext = NULL;
	CRL_DIST_POINTS *crldp;
	int nid = NID_crl_distribution_points;

	if ((crldp = ext_data_crl_distribution_points_new(uris, nuris)) == NULL)
		goto err;

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_NONCRITICAL, crldp);

 err:
	CRL_DIST_POINTS_free(crldp);

	return ext;
}

/*
 * RFC 5280, section 4.2.2.1
 * RFC 5280, section 4.2.2.2
 */

static ACCESS_DESCRIPTION *
ext_data_access_description_new(int nid, const char *uri)
{
	ACCESS_DESCRIPTION *ad;

	if ((ad = ACCESS_DESCRIPTION_new()) == NULL)
		goto err;
	assert(ad->method != NULL);
	assert(ad->location != NULL);

	ASN1_OBJECT_free(ad->method);
	if ((ad->method = OBJ_nid2obj(nid)) == NULL)
		goto err;
	GENERAL_NAME_free(ad->location);
	if ((ad->location = ext_data_general_name_from_uri(uri)) == NULL)
		goto err;

	return ad;

 err:
	ACCESS_DESCRIPTION_free(ad);

	return NULL;
}

static int
ext_data_information_access_add_description(STACK_OF(ACCESS_DESCRIPTION) **ia,
    const struct access_method *am)
{
	ACCESS_DESCRIPTION *ad;
	int ret = 0;

	if ((ad = ext_data_access_description_new(am->nid, am->uri)) == NULL)
		goto err;

	if (*ia == NULL)
		*ia = AUTHORITY_INFO_ACCESS_new();
	if (*ia == NULL)
		goto err;

	if ((sk_ACCESS_DESCRIPTION_push(*ia, ad)) <= 0)
		goto err;
	ad = NULL;

	ret = 1;

 err:
	ACCESS_DESCRIPTION_free(ad);

	return ret;
}

/*
 * authorityInfoAccess (non-critical)
 *
 * CA/EE certs: MUST be present
 * TA certs: MUST NOT be present
 *
 * Currently only supports one access_method.
 *
 * RFC 5280, section 4.2.2.1.
 */

X509_EXTENSION *
ext_authority_info_access_new(const struct access_method *am)
{
	X509_EXTENSION *ext = NULL;
	STACK_OF(ACCESS_DESCRIPTION) *aia = NULL;
	int nid = NID_info_access;

	if (!ext_data_information_access_add_description(&aia, am))
		goto err;

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_NONCRITICAL, aia);

 err:
	sk_ACCESS_DESCRIPTION_pop_free(aia, ACCESS_DESCRIPTION_free);

	return ext;
}

/*
 * subjectInfoAccess (non-critical)
 *
 * MUST be present, URIs listed in descending order of preference
 *
 * For EE certs, there must only be the NID_signedObject accessMethod. All URIs
 * point at the signed object verified by this EE cert. One URI MUST be of type
 * rsync.
 *
 * RFC 5280, section 4.2.2.2.
 */

X509_EXTENSION *
ext_subject_info_access_new(const struct access_method ams[], size_t nams)
{
	X509_EXTENSION *ext = NULL;
	STACK_OF(ACCESS_DESCRIPTION) *sia = NULL;
	int nid = NID_sinfo_access;
	size_t i;

	for (i = 0; i < nams; i++) {
		if (!ext_data_information_access_add_description(&sia, &ams[i]))
			goto err;
	}

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_NONCRITICAL, sia);

 err:
	sk_ACCESS_DESCRIPTION_pop_free(sia, ACCESS_DESCRIPTION_free);

	return ext;
}

/*
 * RFC 5280, section 4.2.1.4
 */

static STACK_OF(POLICYQUALINFO) *
ext_data_cpsuri_new(const char *uri)
{
	STACK_OF(POLICYQUALINFO) *qualifiers = NULL;
	POLICYQUALINFO *cps = NULL;

	/* XXX - validate uri */

	if ((cps = POLICYQUALINFO_new()) == NULL)
		goto err;
	assert(cps->pqualid == NULL);
	assert(cps->d.cpsuri == NULL);

	if ((cps->pqualid = OBJ_nid2obj(NID_id_qt_cps)) == NULL)
		goto err;

	if ((cps->d.cpsuri = ext_data_ia5string_from_uri(uri)) == NULL)
		goto err;

	if ((qualifiers = sk_POLICYQUALINFO_new_null()) == NULL)
		goto err;
	if ((sk_POLICYQUALINFO_push(qualifiers, cps)) <= 0)
		goto err;
	cps = NULL;

	return qualifiers;

 err:
	sk_POLICYQUALINFO_pop_free(qualifiers, POLICYQUALINFO_free);
	POLICYQUALINFO_free(cps);

	return NULL;
}

static STACK_OF(POLICYINFO) *
ext_data_certificate_policies_new(int nid, const char *cpsuri)
{
	STACK_OF(POLICYINFO) *policies = NULL;
	POLICYINFO *policy = NULL;

	if ((policy = POLICYINFO_new()) == NULL)
		goto err;
	assert(policy->policyid != NULL);
	assert(policy->qualifiers == NULL);

	ASN1_OBJECT_free(policy->policyid);
	if ((policy->policyid = OBJ_nid2obj(nid)) == NULL)
		goto err;

	if (cpsuri != NULL) {
		if ((policy->qualifiers = ext_data_cpsuri_new(cpsuri)) == NULL)
			goto err;
	}

	if ((policies = sk_POLICYINFO_new_null()) == NULL)
		goto err;
	if (sk_POLICYINFO_push(policies, policy) <= 0)
		goto err;
	policy = NULL;

	return policies;

 err:
	sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
	POLICYINFO_free(policy);

	return NULL;
}

/*
 * certificatePolicies (critical)
 *
 * Pass the policy's NID and a valid URI pointing at the CPS. If cpsuri is NULL,
 * no policy qualifiers are included.
 *
 * RFC 5280, section 4.2.1.4.
 */

X509_EXTENSION *
ext_certificate_policies_new(int cpnid, const char *cpsuri)
{
	X509_EXTENSION *ext = NULL;
	STACK_OF(POLICYINFO) *pols;
	int nid = NID_certificate_policies;

	if ((pols = ext_data_certificate_policies_new(cpnid, cpsuri)) == NULL)
		goto err;

	ext = X509V3_EXT_i2d(nid, X509V3_EXT_CRITICAL, pols);

 err:
	sk_POLICYINFO_pop_free(pols, POLICYINFO_free);

	return ext;
}
