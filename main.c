#include <err.h>
#include <stdio.h>
#include <unistd.h>

#include "cert.h"

void
usage(void)
{
	fputs("cert [-v] [file]\n", stderr);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct cert_config	*config;
	struct cert		*cert;
	int			 ch;
	int			 verbose = 0;

	while ((ch = getopt(argc, argv, "vh")) != -1) {
		switch (ch) {
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

	config = cert_config_new();
	cert = cert_create(config);
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
