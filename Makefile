CLANG ?= clang
STRIP ?= llvm-strip
OBJCOPY ?= llvm-objcopy
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.DEFAULT_GOAL := build
.PHONY: generate

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

build: generate main.go
	go build ./

mount:
	sudo mount -t bpf none /sys/fs/bpf
	mkdir /sys/fs/bpf/global
