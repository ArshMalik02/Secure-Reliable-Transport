CC=gcc
CFLAGS=-I/opt/homebrew/Cellar/openssl@3/3.4.0/include -L/opt/homebrew/Cellar/openssl@3/3.4.0/lib -lssl -lcrypto

SOURCES=server.c client.c transport.c io.c security.c sec.c
HEADERS=transport.h io.h consts.h security.h sec.h

all: clean build

default: build

build:	${SOURCES}
	${CC} -o server server.c transport.c io.c security.c sec.c ${CFLAGS}
	${CC} -o client client.c transport.c io.c security.c sec.c ${CFLAGS}

clean:
	rm -rf server client *.bin *.out *.dSYM *.zip

zip: clean
	rm -f project2.zip
	mkdir -p project
	cp README.md server.c client.c transport.c io.c security.c sec.c transport.h io.h consts.h security.h sec.h Makefile project
	zip project2.zip project/*
	rm -rf project
