all: spritz.a spritz-hash.exe

spritz.a: spritz.h spritz.c
	gcc -std=c11 -O3 -c spritz.c 
	ar -r spritz.a spritz.o

spritz-hash.exe: spritz.h hash.c lineio.h lineio.c spritz.a
	gcc -std=c11 -O3 hash.c lineio.c spritz.a -o spritz-hash
