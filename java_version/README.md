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
