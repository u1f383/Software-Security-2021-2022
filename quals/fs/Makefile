all:
	gcc -fsanitize=address -o main main.c fs.c gc.c user.c mycrypto.c -lcrypto

qq:
	gcc -g -o main main.c fs.c gc.c user.c mycrypto.c -lcrypto

debug:
	gcc -fsanitize=address -g -o main main.c fs.c gc.c user.c mycrypto.c -lcrypto
