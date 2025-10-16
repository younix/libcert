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

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "cert.h"

void
usage(void)
{
	fputs("cert [-vh] [-a time] [-b time] [-I issuer] [-S subject]"
	    " [-r uri] [-s serial]\n"
	    "     [-t type] [-c cps] [file]\n", stderr);

	exit(1);
}

void
issuer(struct cert_config *config, char *name)
{
	char *key;

	if ((key = strsep(&name, "=")) == NULL)
		errx(1, "illegal name: %s", name);
	if (name == NULL || name[0] == '\0')
		errx(1, "empty issuer name");

	if (strcmp(key, "C") == 0)
		cert_config_issuer_c(config, name);
	else if (strcmp(key, "O") == 0)
		cert_config_issuer_o(config, name);
	else if (strcmp(key, "OU") == 0)
		cert_config_issuer_ou(config, name);
	else if (strcmp(key, "DNQ") == 0)
		cert_config_issuer_dnq(config, name);
	else if (strcmp(key, "ST") == 0)
		cert_config_issuer_st(config, name);
	else if (strcmp(key, "CN") == 0)
		cert_config_issuer_cn(config, name);
	else if (strcmp(key, "SER") == 0)
		cert_config_issuer_ser(config, name);
	else
		errx(1, "unknown issuer name: %s", key);
}

void
subject(struct cert_config *config, char *name)
{
	char *key;

	if ((key = strsep(&name, "=")) == NULL)
		errx(1, "illegal name: %s", name);
	if (name == NULL || name[0] == '\0')
		errx(1, "empty subject name");

	if (strcmp(key, "C") == 0)
		cert_config_subject_c(config, name);
	else if (strcmp(key, "O") == 0)
		cert_config_subject_o(config, name);
	else if (strcmp(key, "OU") == 0)
		cert_config_subject_ou(config, name);
	else if (strcmp(key, "DNQ") == 0)
		cert_config_subject_dnq(config, name);
	else if (strcmp(key, "ST") == 0)
		cert_config_subject_st(config, name);
	else if (strcmp(key, "CN") == 0)
		cert_config_subject_cn(config, name);
	else if (strcmp(key, "SER") == 0)
		cert_config_subject_ser(config, name);
	else
		errx(1, "unknown subject name: %s", key);
}

time_t
date2time(const char *date)
{
	struct tm	 tm;
	char		*fmt;

	if (strlen(date) == 10)
		fmt = "%F";
	else if (strlen(date) == 19)
		fmt = "%FT%T";
	else
		return -1;

	memset(&tm, 0, sizeof tm);
	if (strptime(date, fmt, &tm) == NULL)
		return -1;

	return timegm(&tm);
}

int
main(int argc, char *argv[])
{
	struct cert_config	*config;
	struct cert		*cert;
	const char		*errstr = NULL;
	X509			*x509;
	int64_t		 	 serial;
	time_t			 notBefore = 0;
	time_t			 notAfter = 0;
	int			 verbose = 0;
	int			 ch;

	if ((config = cert_config_new()) == NULL)
		err(1, "cert_config_new");

	while ((ch = getopt(argc, argv, "a:b:c:I:S:t:r:vs:h")) != -1) {
		switch (ch) {
		case 'a':
			notAfter = date2time(optarg);
			if (notAfter == -1)
				errx(1, "invalid date: %s", optarg);
			break;
		case 'b':
			notBefore = date2time(optarg);
			if (notBefore == -1)
				errx(1, "invalid date: %s", optarg);
			break;
		case 'c':
			cert_config_set_cps(config, optarg);
			break;
		case 'I':
			issuer(config, optarg);
			break;
		case 'S':
			subject(config, optarg);
			break;
		case 's':
			serial = strtonum(optarg, 0, INT64_MAX, &errstr);
			if (errstr)
				errx(1, "strtonum: %s: %s", optarg, errstr);
			cert_config_serial(config, serial);
			break;
		case 't':
			if (strcmp(optarg, "ee") == 0)
				cert_config_set_ee(config);
			else if (strcmp(optarg, "ca") == 0)
				cert_config_set_ca(config);
			else if (strcmp(optarg, "ta") == 0)
				cert_config_set_ta(config);
			else
				errx(1, "unknown certificate type: %s", optarg);
			break;
		case 'r':
			if (cert_config_add_crl_uri(config, optarg) == 0)
				err(1, "cert_config_add_crl_uri");
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	cert_config_notBefore(config, notBefore);
	cert_config_notAfter(config, notAfter);

	if ((cert = cert_new()) == NULL)
		err(1, "cert_new");

	cert_create(cert, config);
	cert_config_free(config);

	x509 = cert_get_x509(cert);

	if (verbose)
		X509_print_fp(stdout, x509);

	if (argc == 1) {
		FILE *fh;
		char *path = argv[0];

		if ((fh = fopen(path, "w")) == NULL)
			err(1, "%s", path);

		if (PEM_write_X509(fh, x509) == 0)
			err(1, "%s", path);

		if (fclose(fh) == EOF)
			err(1, "%s", path);
	}

	cert_free(cert);

	return 0;
}
