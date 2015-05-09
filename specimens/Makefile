# Build the example specimen binaries into ./bin/
CC      ?= cc
CFLAGS  ?= -O0 -g -Wall -Wextra -pthread
SRC     := $(wildcard src/*.c)
BIN     := $(patsubst src/%.c,bin/%,$(SRC))

# l2demo is freestanding/static/no-PIE so its entry point is its own code.
L2FLAGS := -O0 -no-pie -static -nostdlib -ffreestanding -fno-stack-protector

.PHONY: all clean
all: $(BIN)

bin/l2demo: src/l2demo.c | bin
	$(CC) $(L2FLAGS) -o $@ $<

bin/httpsbeacon: src/httpsbeacon.c | bin
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

bin/%: src/%.c | bin
	$(CC) $(CFLAGS) -o $@ $<

bin:
	mkdir -p bin

clean:
	rm -rf bin
