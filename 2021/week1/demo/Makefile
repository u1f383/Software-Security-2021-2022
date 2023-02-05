all: demo_shellcode demo_ROP demo_BOF1 demo_BOF2_leak_canary demo_canary demo_GOT demo_one_gadget_with_ROP demo_stack_pivoting demo_fmt

demo_shellcode:
	gcc -g -z execstack -o $@ $@.c
demo_BOF1:
	gcc -g -no-pie -fno-stack-protector -o $@ $@.c
demo_BOF2_leak_canary:
	gcc -g -no-pie -o $@ $@.c
demo_canary:
	gcc -Wl,--dynamic-linker=/usr/src/glibc/glibc_dbg/elf/ld.so -g -o $@ $@.c
demo_GOT:
	gcc -z lazy -Wl,--dynamic-linker=/usr/src/glibc/glibc_dbg/elf/ld.so -g -o $@ $@.c
demo_ROP:
	gcc -g -no-pie -static -fno-stack-protector -o $@ $@.c
demo_one_gadget_with_ROP:
	gcc -g -fno-stack-protector -o $@ $@.c
demo_stack_pivoting:
	gcc -g -no-pie -static -fno-stack-protector -o $@ $@.c
demo_fmt:
	gcc -g -z lazy -no-pie -o $@ $@.c