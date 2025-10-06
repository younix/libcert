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

/*
 * IWYU pragma: private
 */

#ifndef __OPENSSL_COMPAT_H__
#define __OPENSSL_COMPAT_H__

#include <openssl/bn.h>		/* IWYU pragma: keep */
#include <openssl/cms.h>	/* IWYU pragma: keep */
#include <openssl/evp.h>	/* IWYU pragma: keep */
#include <openssl/objects.h>	/* IWYU pragma: keep */
#include <openssl/rsa.h>	/* IWYU pragma: keep */
#include <openssl/x509.h>	/* IWYU pragma: keep */
#include <openssl/x509v3.h>	/* IWYU pragma: keep */

#include "cert.h"

/* X.690, 8.2.2 */
#ifndef ASN1_BOOLEAN_FALSE
#define ASN1_BOOLEAN_FALSE	0x00
#endif

/* X.690, 11.1 */
#ifndef ASN1_BOOLEAN_TRUE
#define ASN1_BOOLEAN_TRUE	0xff
#endif

/* RFC 5280, section 4.1.2.1 */
#ifndef X509_VERSION_3
#define X509_VERSION_3		2
#endif

/* RFC 5280, section 5.1.2.1 */
#ifndef X509_CRL_VERSION_2
#define X509_CRL_VERSION_2	1
#endif

/* RFC 2986, section 4.1 */
#ifndef X509_REQ_VERSION_1
#define X509_REQ_VERSION_1	0
#endif

#ifndef X509V3_EXT_CRITICAL
#define X509V3_EXT_CRITICAL	1
#endif

#ifndef X509V3_EXT_NONCRITICAL
#define X509V3_EXT_NONCRITICAL	0
#endif

#ifndef HAVE_EVP_PKEY_CTX_SET1_RSA_KEYGEN_PUBEXP
/* Of course it isn't const correct. */
int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
#endif

#ifndef HAVE_X509V3_CACHE_EXTENSIONS
int X509v3_cache_extensions(X509 *cert);
#endif

/*
 * Initialize the crypto library.
 *
 * Provide missing obj_mac.h entries. This calls OBJ_create(3) under the hood.
 * XXX: This would be a bit less offensive if we only added a NID...
 */
void compat_init(void);

#ifndef NID_id_ct_xml
extern int NID_id_ct_xml;
extern const char *SN_id_ct_xml;
/* no long name */
#endif

#ifndef NID_ipAddr_asNumber
extern int NID_ipAddr_asNumber;
extern const char *SN_ipAddr_asNumber;
/* no long name */
#endif

#ifndef NID_ipAddr_asNumberv2
extern int NID_ipAddr_asNumberv2;
extern const char *SN_ipAddr_asNumberv2;
/* no long name */
#endif

#ifndef NID_rpkiManifest
extern int NID_rpkiManifest;
extern const char *SN_rpkiManifest;
extern const char *LN_rpkiManifest;
#endif

#ifndef NID_signedObject
extern int NID_signedObject;
extern const char *SN_signedObject;
extern const char *LN_signedObject;
#endif

#ifndef NID_rpkiNotify
extern int NID_rpkiNotify;
extern const char *SN_rpkiNotify;
extern const char *LN_rpkiNotify;
#endif

#endif /* __OPENSSL_COMPAT_H__ */
