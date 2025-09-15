CFLAGS += -fPIC
CFLAGS += -Wall -Wextra -pedantic -Wno-unused-parameter
LDFLAGS += -lcrypto -lssl -lcrypto

.PHONY: all clean test

OBJ = cert.o keypair.o x509_extensions.o openssl-compat.o util.o \
    bytestring/bs_ber.o bytestring/bs_cbb.o bytestring/bs_cbs.o

all: cert cert-static

cert: main.c libcert.so
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) main.c -L. -lcert

cert-static: main.c libcert.a
	$(CC) -static -o $@ $(CFLAGS) $(LDFLAGS) main.c -L. -lcert

libcert.so: $(OBJ)
	$(CC) -shared -o libcert.so $(OBJ)

libcert.a: $(OBJ)
	$(AR) rcs libcert.a $(OBJ)

bytestring/bs_ber.o: bytestring/bs_ber.c
	$(CC) -c $(CFLAGS) -o $@ bytestring/bs_ber.c
bytestring/bs_cbb.o: bytestring/bs_cbb.c
	$(CC) -c $(CFLAGS) -o $@ bytestring/bs_cbb.c
bytestring/bs_cbs.o: bytestring/bs_cbs.c
	$(CC) -c $(CFLAGS) -o $@ bytestring/bs_cbs.c

clean:
	rm -f *.a *.so $(OBJ) cert cert-static

test: cert cert-static
	LD_LIBRARY_PATH=. ./cert
	./cert-static
