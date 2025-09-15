#include <unistd.h>

#include "cert.h"

void
usage(void)
{
	fputs("cert [-v]\n", stderr);
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

	cert_free(cert);

	return 0;
}
