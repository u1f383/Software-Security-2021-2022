all:
	Got2win
	Rop2orw

Got2win:
	gcc -g -no-pie -o $@ $@.c

Rop2orw:
	gcc -g -no-pie -static -fno-stack-protector -o $@ $@.c -lseccomp