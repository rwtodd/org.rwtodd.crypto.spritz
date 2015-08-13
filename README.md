# spritz_cipher
A scala implementation of the Spritz sponge-like stream cipher.

I read about this fun cipher [here (RS14.pdf)][1], and
decided to implement it in scala.  It has all the 
methods int he PDF spec, and exposes the ones like
`absorb` and `squeeze` that are used to encrypt, decrypt,
and hash.

The provided companion object SpritzCipher is intended to
cover the simple cases. It can compute hashes, and encrypt
or decrypt a stream.

```
// get a 256-bit hash of some bytes
val  hash = SpritzCipher.hash(256, inbytes)

// encrypt a stream 
SpritzCipher.encrypt(password, instream, outstream)

// decrypt a stream
SpritzCipher.encrypt(password, instream, outstream)
```

I've got spritz_hash.scala and spritz_crypt.scala, which
have objects for use from the command line. Right now,
they are _too_ basic, but they are good enough for testing.

```
> scala rwt.spritz.Hash *.scala
spritz.scala: c24f02ce8c65f86cc61dbbf486803f5ff7c93e2c2201037c5e99c1421706eeae
spritz_crypt.scala: d9e3ae2e8ab2c869149304323920301216a7e688ada88d9350816260e7f35bde
spritz_hash.scala: 71aa2708801ec8756765bbebe1bfcac41f669b4df811bfa84e0c05dcf351b09a

> scala rwt.spritz.Crypt <<password>> file2 file2
```

[1]: http://people.csail.mit.edu/rivest/pubs/RS14.pdf
