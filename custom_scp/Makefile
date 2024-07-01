CC = gcc
LIBS = -lgcrypt -lm
INSTALL_DIR = /usr/local

all: purdec purenc

purdec: purdec.c
	$(CC) -o purdec purdec.c $(LIBS)

purenc: purenc.c
	$(CC) -o purenc purenc.c $(LIBS)

clean:
	rm -f purdec purenc
