all: libspritz.a spritz-hash.exe spritz-crypt.exe

clean:
	-rm *.o *.a *~ spritz-hash.exe spritz-crypt.exe

libspritz.a: spritz.h spritz.c
	gcc -std=c11 -O3 -c spritz.c 
	ar -r libspritz.a spritz.o

spritz-crypt.exe: spritz.h crypt.c  libspritz.a
	gcc -std=c11 -O3 crypt.c  -L. -lspritz -o spritz-crypt
	strip spritz-crypt.exe

spritz-hash.exe: spritz.h hash.c libspritz.a
	gcc -std=c11 -O3 hash.c  -L. -lspritz -o spritz-hash
	strip spritz-hash.exe
