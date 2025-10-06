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

#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "bytestring/bytestring.h"
#include "constant_time.h"

/*
 * Compute key identifier: take the SHA-1 of the bit string of the public key,
 * excluding tag, length, and unused bits, as in RFC 5280, Section 4.2.1.1.
 */
int
key_identifier(EVP_PKEY *pkey, unsigned char *md, unsigned int *md_len)
{
	X509_PUBKEY *x509_pubkey = NULL;
	const unsigned char *der;
	int der_len;
	int ret = 0;

	if (*md_len < SHA_DIGEST_LENGTH)
		goto err;

	if (!X509_PUBKEY_set(&x509_pubkey, pkey))
		goto err;
	if (!X509_PUBKEY_get0_param(NULL, &der, &der_len, NULL, x509_pubkey))
		goto err;
	if (!EVP_Digest(der, der_len, md, md_len, EVP_sha1(), NULL))
		goto err;

	ret = 1;

 err:
	X509_PUBKEY_free(x509_pubkey);

	return ret;
}
