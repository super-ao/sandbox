CC = clang

all: probe main

CFLAGS= -Wno-missing-declarations -Wall -Wextra -O2

probe: src/probe.bpf.c
	@$(CC) $(CFLAGS) -g -target bpf -c src/probe.bpf.c -o build/probe.bpf.o -Iinclude

main: src/main.c
	@$(CC) $(CFLAGS) src/main.c -o build/main -lbpf -Iinclude

run: main probe
	@sudo build/main

clean:
	@rm -rf build/*
