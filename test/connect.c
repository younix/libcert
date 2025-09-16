#include <sys/socket.h>
#include <sys/wait.h>

#include <err.h>
#include <stdio.h>
#include <unistd.h>

#include "../cert.h"
#include <tls.h>

void
client(int s)
{
	struct tls_config	*config;
	struct tls		*tls;

	if ((tls = tls_client()) == NULL)
		err(1, "tls_client");

	if ((config = tls_config_new()) == NULL)
		err(1, "tls_config_new");

	/* The server will use a selfsigned certificate. */
	tls_config_insecure_noverifyname(config);

	if (tls_configure(tls, config) == -1)
		errx(1, "tls_configure: %s", tls_error(tls));

	if (tls_connect_socket(tls, s, "localhost") == -1)
		err(1, "tls_connect_socket");

	if (tls_close(tls) == -1)
		errx(1, "tls_close: %s", tls_error(tls));

	if (close(s) == -1)
		err(1, "close");
}

void
server(int s)
{
	struct tls		*tls;
	struct tls		*ctx;
	struct tls_config	*config;
	uint8_t			*key;
	uint8_t			*crt;
	size_t			 keylen;
	size_t			 crtlen;

	struct cert_config      *cert_config;
	struct cert             *cert;

	/*
	 * Create Key and Certificate with libcert
	 */
	if ((cert_config = cert_config_new()) == NULL)
		err(1, "cert_config_new");

	if ((cert = cert_create(cert_config)) == NULL)
		err(1, "cert_create");

	if (cert_key_data(cert, &key, &keylen) == 0)
		err(1, "cert_key_data");

	if (cert_crt_data(cert, &crt, &crtlen) == 0)
		err(1, "cert_crt_data");

	cert_config_free(cert_config);
	cert_free(cert);

	/*
	 * Use Key and Certificate with libtls
	 */
	if ((tls = tls_server()) == NULL)
		err(1, "tls_server");

	if ((config = tls_config_new()) == NULL)
		err(1, "tls_config_new");

	tls_config_set_key_mem(config, key, keylen);
	tls_config_set_cert_mem(config, crt, crtlen);

	if (tls_configure(tls, config) == -1)
		errx(1, "tls_configure: %s", tls_error(tls));

	if (tls_accept_socket(tls, &ctx, s) == -1)
		errx(1, "tls_accept_socket: %s", tls_error(tls));

	if (tls_close(ctx) == -1)
		errx(1, "tls_close: %s", tls_error(tls));

	if (close(s) == -1)
		err(1, "close");
}

int
main(void)
{
	int sv[2];
	int status;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		err(1, "socketpair");

	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		client(sv[0]);
		break;
	default:
		server(sv[1]);
		wait(&status);
		if (WEXITSTATUS(status) != 0)
			errx(1, "client: %d", status);
	}

	return 0;
}
