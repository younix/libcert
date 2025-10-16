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

#ifndef CERT_H
#define CERT_H

#include <openssl/x509.h>

struct cert_config;
struct cert;

struct cert_config *
	cert_config_new(void);
void	cert_config_free(struct cert_config *);
void	cert_config_set_ee(struct cert_config *);
void	cert_config_set_ca(struct cert_config *);
void	cert_config_set_ta(struct cert_config *);
void	cert_config_serial(struct cert_config *, uint64_t);
void	cert_config_notBefore(struct cert_config *, time_t);
void	cert_config_notAfter(struct cert_config *, time_t);
int	cert_config_add_crl_uri(struct cert_config *, const char *);
void	cert_config_set_cps(struct cert_config *, const char *);

void	cert_config_issuer_c(struct cert_config *, const char *);
void	cert_config_issuer_o(struct cert_config *, const char *);
void	cert_config_issuer_ou(struct cert_config *, const char *);
void	cert_config_issuer_dnq(struct cert_config *, const char *);
void	cert_config_issuer_st(struct cert_config *, const char *);
void	cert_config_issuer_cn(struct cert_config *, const char *);
void	cert_config_issuer_ser(struct cert_config *, const char *);

void	cert_config_subject_c(struct cert_config *, const char *);
void	cert_config_subject_o(struct cert_config *, const char *);
void	cert_config_subject_ou(struct cert_config *, const char *);
void	cert_config_subject_dnq(struct cert_config *, const char *);
void	cert_config_subject_st(struct cert_config *, const char *);
void	cert_config_subject_cn(struct cert_config *, const char *);
void	cert_config_subject_ser(struct cert_config *, const char *);

struct cert *
	cert_new(void);
int	cert_load_issuer_key(struct cert *, const char *);
int	cert_load_subject_key(struct cert *, const char *);
int	cert_create(struct cert *cert, struct cert_config *);
void	cert_free(struct cert *);
int	cert_crt_data(struct cert *, uint8_t **, size_t *);
int	cert_key_data(struct cert *, uint8_t **, size_t *);
X509 *	cert_get_x509(struct cert *);

#endif
