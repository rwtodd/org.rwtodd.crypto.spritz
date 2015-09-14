# spritz cipher

Implementations of the Spritz sponge-like stream cipher in
`scala`, `java`, `go`, `c`, `forth`, and `c++` (in that order).  
The `java` and `scala` 
versions have both hashing and encryption convenience 
functions. The others have the full algorithm but 
are only set up to help you hash. 


## Story

I read about this fun cipher [here (RS14.pdf)][1], and
decided to implement it in scala.  After that, I converted it
to java to compare the two.  Here's what I found:

  * The java source and scala source were roughly the same size
  * `javac` produced 1 class file (4kb), while `scalac` produced
     11 class files (24kb).

I decided to stick with the java version!

_Edit 2015-08-15_: I also implemented enough to do hashing in golang. Check
out the `go_version` subdirectory's README.md to see how that went!  Spoiler
alert: the coding was great but it ran at half speed compared to scala.

_Edit: 2015-08-25_: I made a C version to see how much it would 
trounce the java version. Surprise: the java was faster!  I'm a 
little stumped as to why, since the C version allocates once and
the rest is just fread+computation.  That makes me think fread 
is the achilles' heel here.  If anyone can improve it while 
sticking to the C library (e.g., no `mmap`), I'd be interested
in how.

_Edit: 2015-09-12_: I made a forth version. On interpreted gforth
it runs about 4.8 times slower than java. But it was fun to write!
When I compile it with MPE Forth, it's about 1.4x slower than
the java. Much more respectable.

_Edit: 2015-09-13_: I converted the C to C++ because I wanted
to see if I could feel a productivity difference using iterators
for everything.  My findings are in the readme in that directory.

About the Java Version
----------------------

The class has all the 
methods in the PDF spec, and exposes the ones like
`absorb` and `squeeze` that are used to encrypt, decrypt,
and hash.

The provided static methods are intended to
cover the simple cases. It can compute hashes, and encrypt
or decrypt a stream.

```
// get a 256-bit hash of some bytes
byte[]  hash = SpritzCipher.hash(256, inbytes)

// encrypt a stream 
SpritzCipher.encrypt(password, instream, outstream)

// decrypt a stream
SpritzCipher.decrypt(password, instream, outstream)
```

I made command-line programs for hashing and encrypting. 

```
> java rwt.spritz.Hash *.scala
spritz.scala: c24f02ce8c65f86cc61dbbf486803f5ff7c93e2c2201037c5e99c1421706eeae
spritz_crypt.scala: d9e3ae2e8ab2c869149304323920301216a7e688ada88d9350816260e7f35bde
spritz_hash.scala: 71aa2708801ec8756765bbebe1bfcac41f669b4df811bfa84e0c05dcf351b09a

> java rwt.spritz.Crypt <<password>> file1 file2
```

[1]: http://people.csail.mit.edu/rivest/pubs/RS14.pdf
