CLANG?=clang

.DEFAULT_GOAL:=$(addsuffix .elf,$(wildcard *.c))

%.c.elf: %.c
	$(CLANG) -target bpf -O2 -nostdinc -Wall -Werror -Wno-missing-braces -isystem headers/ -c $< -o $@
