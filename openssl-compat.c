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

#include <err.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "cert_internal.h"
#include "cert.h"

/*
 * EVP_PKEY_CTX_set1_rsa_keygen_pubexp() is the OpenSSL 3 replacement API
 * for EVP_PKEY_CTX_set_rsa_keygen_pubexp(). It makes a copy of |pubexp|
 * rather than transferring ownership. Of course, |pubex| should have been
 * const. This is provided here to avoid ugly warnings when using OpenSSL 3.
 */

#ifndef HAVE_EVP_PKEY_CTX_SET1_RSA_KEYGEN_PUBEXP
int
EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp)
{
	BIGNUM *bn = NULL;
	int ret = -1;

	if (!BN_is_odd(pubexp))
		goto err;
	if ((bn = BN_dup(pubexp)) == NULL)
		goto err;

	ret = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, bn);
	bn = NULL;

 err:
	BN_free(bn);

	return ret;
}
#endif

/*
 * X509v3_cache_extensions() caches the X.509v3 extensions and preforms some
 * sanity checking. Trivial wrapper to make a well-known trick more obvious
 * in the callers.
 */

#ifndef HAVE_X509V3_CACHE_EXTENSIONS
int
X509v3_cache_extensions(X509 *cert)
{
	return X509_check_purpose(cert, -1, 0) == 1;
}
#endif

/*
 * Provide missing obj_mac.h entries.
 */

#ifndef NID_id_ct_xml
int NID_id_ct_xml;
const char *SN_id_ct_xml;
static ASN1_OBJECT *id_ct_xml_oid;
#endif

#ifndef NID_ipAddr_asNumber
int NID_ipAddr_asNumber;
const char *SN_ipAddr_asNumber;
static ASN1_OBJECT *ipAddr_asNumber_oid;
#endif

#ifndef NID_ipAddr_asNumberv2
int NID_ipAddr_asNumberv2;
const char *SN_ipAddr_asNumberv2;
static ASN1_OBJECT *ipAddr_asNumberv2_oid;
#endif

#ifndef NID_rpkiManifest
int NID_rpkiManifest;
const char *SN_rpkiManifest;
const char *LN_rpkiManifest;
static ASN1_OBJECT *rpkiManifest_oid;
#endif

#ifndef NID_signedObject
int NID_signedObject;
const char *SN_signedObject;
const char *LN_signedObject;
static ASN1_OBJECT *signedObject_oid;
#endif

#ifndef NID_rpkiNotify
int NID_rpkiNotify;
const char *SN_rpkiNotify;
const char *LN_rpkiNotify;
static ASN1_OBJECT *rpkiNotify_oid;
#endif

static const struct {
	/* Input. */
	const char *oid;
	const char *sn;
	const char *ln;

	/* Output. */
	int *NID;
	const char **SN;
	const char **LN;
	const unsigned char **OBJ;
	ASN1_OBJECT **obj;
} nids[] = {
#ifndef NID_id_ct_xml
	{
		.oid = "1.2.840.113549.1.9.16.1.28",
		.sn = "id-ct-xml",

		.NID = &NID_id_ct_xml,
		.SN = &SN_id_ct_xml,
		.obj = &id_ct_xml_oid,
	},
#endif
#ifndef NID_ipAddr_asNumber
	{
		.oid = "1.3.6.1.5.5.7.14.2",
		.sn = "ipAddr-asNumber",

		.NID = &NID_ipAddr_asNumber,
		.SN = &SN_ipAddr_asNumber,
		.obj = &ipAddr_asNumber_oid,
	},
#endif
#ifndef NID_ipAddr_asNumberv2
	{
		.oid = "1.3.6.1.5.5.7.14.3",
		.sn = "ipAddr-asNumberv2",

		.NID = &NID_ipAddr_asNumberv2,
		.SN = &SN_ipAddr_asNumberv2,
		.obj = &ipAddr_asNumberv2_oid,
	},
#endif
#ifndef NID_rpkiManifest
	{
		.oid = "1.3.6.1.5.5.7.48.10",
		.sn = "rpkiManifest",
		.ln = "RPKI Manifest",

		.NID = &NID_rpkiManifest,
		.SN = &SN_rpkiManifest,
		.LN = &LN_rpkiManifest,
		.obj = &rpkiManifest_oid,
	},
#endif
#ifndef NID_signedObject
	{
		.oid = "1.3.6.1.5.5.7.48.11",
		.sn = "signedObject",
		.ln = "Signed Object",

		.NID = &NID_signedObject,
		.SN = &SN_signedObject,
		.LN = &LN_signedObject,
		.obj = &signedObject_oid,
	},
#endif
#ifndef NID_rpkiNotify
	{
		.oid = "1.3.6.1.5.5.7.48.13",
		.sn = "rpkiNotify",
		.ln = "RPKI Notify",

		.NID = &NID_rpkiNotify,
		.SN = &SN_rpkiNotify,
		.LN = &LN_rpkiNotify,
		.obj = &rpkiNotify_oid,
	},
#endif
	{
		.ln = "dummy to avoid undefined behavior",
	},
};

static int
compat_load_nids(struct cert *cert)
{
	size_t i;

	for (i = 0; i < sizeof(nids) / sizeof(nids[0]); i++) {
		if (nids[i].oid == NULL)
			continue;

		*nids[i].NID = OBJ_create(nids[i].oid, nids[i].sn, nids[i].ln);
		if (*nids[i].NID == NID_undef) {
			cert->errstr = "OBJ_create";	/* XXX: nids[i].sn */
			return 0;
		}

		if (nids[i].SN != NULL)
			*nids[i].SN = nids[i].sn;
		if (nids[i].LN != NULL)
			*nids[i].LN = nids[i].ln;
		if (nids[i].oid != NULL) {
			if ((*nids[i].obj = OBJ_nid2obj(*nids[i].NID)) == NULL){
				cert->errstr = "OBJ_nid2obj";
				return 0;
			}
		}
	}

	return 1;
}

int
compat_init(struct cert *cert)
{
	if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)) {
		cert->errstr = "OPENSSL_init_crypto";
		return 0;
	}

	return compat_load_nids(cert);
}
