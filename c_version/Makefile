all: libspritz.a spritz-hash.exe spritz-crypt.exe

clean:
	rm *.o *.a *~ spritz-hash.exe

libspritz.a: spritz.h spritz.c
	gcc -std=c11 -O3 -c spritz.c 
	ar -r libspritz.a spritz.o

spritz-crypt.exe: spritz.h crypt.c lineio.h lineio.c libspritz.a
	gcc -std=c11 -O3 crypt.c lineio.c -L. -lspritz -o spritz-crypt

spritz-hash.exe: spritz.h hash.c lineio.h lineio.c libspritz.a
	gcc -std=c11 -O3 hash.c lineio.c -L. -lspritz -o spritz-hash
