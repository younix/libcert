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
#include <unistd.h>

#include "cert.h"

void
usage(void)
{
	fputs("cert [-vh] [-s serial] [file]\n", stderr);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct cert_config	*config;
	struct cert		*cert;
	const char		*errstr = NULL;
	int64_t		 	 serial = 0;
	int			 verbose = 0;
	int			 ch;

	while ((ch = getopt(argc, argv, "vs:h")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		case 's':
			serial = strtonum(optarg, 0, INT64_MAX, &errstr);
			if (errstr)
				errx(1, "strtonum: %s: %s", optarg, errstr);
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ((config = cert_config_new()) == NULL)
		err(1, "cert_config_new");

	cert_config_serial(config, serial);

	if ((cert = cert_new()) == NULL)
		err(1, "cert_new");

	cert_create(cert, config);
	cert_config_free(config);

	if (verbose)
		X509_print_fp(stdout, cert->x509);

	if (argc == 1) {
		FILE *fh;
		char *path = argv[0];

		if ((fh = fopen(path, "w")) == NULL)
			err(1, "%s", path);

		if (PEM_write_X509(fh, cert->x509) == 0)
			err(1, "%s", path);

		if (fclose(fh) == EOF)
			err(1, "%s", path);
	}

	cert_free(cert);

	return 0;
}
