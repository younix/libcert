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
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "cert.h"

/*
 * RFC 7935, section 3: The RSA key pairs used to compute the signatures
 * MUST have a 2048-bit modulus and a public exponent (e) of 65,537.
 */
#define RSA_KEY_SIZE	2048
#define RSA_EXPONENT	65537	/* RSA_F4 */

static EVP_PKEY *
keypair_generate_rsa(struct cert *cert)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL, *ret = NULL;
	BIGNUM *exponent = NULL;

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
		cert->errstr = "EVP_PKEY_CTX_new_id(rsa)";
		goto err;
	}

	/*
	 * With a great API comes great usability...
	 */

	/* For unclear reasons we need to kick off the keygen state machine. */
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		cert->errstr = "EVP_PKEY_keygen_init(rsa)";
		goto err;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) {
		cert->errstr= "EVP_PKEY_CTX_set_rsa_keygen_bits";
		goto err;
	}
	/* 65537 is the default public exponent, but let's make sure. */
	if ((exponent = BN_new()) == NULL) {
		cert->errstr = "BN_new(rsa exp)";
		goto err;
	}
	if (!BN_set_word(exponent, RSA_EXPONENT)) {
		cert->errstr = "BN_set_word(rsa exp)";
		goto err;
	}
	if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, exponent) <= 0) {
		cert->errstr = "EVP_PKEY_CTX_set1_rsa_keygen_bits";
		goto err;
	}

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		cert->errstr = "EVP_PKEY_keygen(rsa)";
		goto err;
	}

	ret = pkey;
	pkey = NULL;

 err:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	BN_free(exponent);

	return ret;
}

static EVP_PKEY *
keypair_generate_ecdsa(struct cert *cert)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL, *ret = NULL;
	int nid;

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL) {
		cert->errstr = "EVP_PKEY_CTX_new_id(P-256)";
		goto err;
	}

	/* For unclear reasons we need to kick off the keygen state machine. */
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		cert->errstr = "EVP_PKEY_keygen_init(P-256)";
		goto err;
	}

	/* NID_X9_62_prime256v1 is a stupid name. */
	if ((nid = EC_curve_nist2nid("P-256")) == NID_undef) {
		cert->errstr = "EC_curve_nist2nid";
		goto err;
	}
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
		cert->errstr = "EVP_PKEY_CTX_set_ec_paramgen_curve_nid()";
		goto err;
	}
	/* Ensure we use parameter encoding via "curve name" (OID). */
	if (EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) <= 0) {
		cert->errstr = "EVP_PKEY_CTX_set_ec_param_enc";
		goto err;
	}

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		cert->errstr = "EVP_PKEY_keygen(P-256)";
		goto err;
	}

	ret = pkey;
	pkey = NULL;

 err:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	return ret;
}

EVP_PKEY *
keypair_generate(struct cert *cert)
{
	switch (cert->config->keytype) {
	case KEYPAIR_RSA:
		return keypair_generate_rsa(cert);
	case KEYPAIR_ECDSA:
		return keypair_generate_ecdsa(cert);
	}

	cert->errstr = "keypair_generate: unreachable";

	return NULL;
}

EVP_PKEY *
keypair_extract_public(EVP_PKEY *pkey)
{
	X509_PUBKEY *x509_pubkey = NULL;
	EVP_PKEY *pubkey = NULL, *ret = NULL;

	if (!X509_PUBKEY_set(&x509_pubkey, pkey)) {
		warnx("X509_PUBKEY_set");
		goto err;
	}
	if ((pubkey = X509_PUBKEY_get(x509_pubkey)) == NULL) {
		warnx("X509_PUBKEY_get");
		goto err;
	}

	ret = pubkey;
	pubkey = NULL;

 err:
	X509_PUBKEY_free(x509_pubkey);
	EVP_PKEY_free(pubkey);

	return ret;
}
