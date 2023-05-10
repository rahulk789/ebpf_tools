# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright (c) 2020 Cloudflare

KERNEL_INC := /usr/include/bpf
VMLINUX := ./vmlinux.h

CC := clang
CFLAGS := -g -O2 -Wall -Wextra
CPPFLAGS := -I$(KERNEL_INC) 

PROGS := sockmap-update sk-lookup-attach redirect.bpf.o

.PHONY: all
all: $(PROGS)

sockmap-update: sockmap_update.c $(KERNEL_INC) 
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

sk-lookup-attach: sk_lookup_attach.c $(KERNEL_INC)  
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

redirect.bpf.o: redirect.bpf.c $(KERNEL_INC) $(VMLINUX)
	$(CC) $(CPPFLAGS) $(CFLAGS) -target bpf -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(PROGS)


