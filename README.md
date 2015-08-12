# spritz_cipher
A scala implementation of the Spritz sponge-like stream cipher.

I read about this fun cipher [here (RS14.pdf)][1], and
decided to implement it in scala.  It has all the 
methods int he PDF spec, and exposes the ones like
`absorb` and `squeeze` that are used to encrypt, decrypt,
and hash.

The provided companion object SpritzCipher is intended to
cover the simple cases. Right now the only two functions
are `hash` and `cipherStream`:

```
// get a 256-bit hash of some bytes
val  hash = SpritzCipher.hash(256, inbytes)

// encode a data buffer against a password
val encoder = SpritzCipher.cipherStream("some password")
encoder.squeezeXOR(my_data)

// you can put an IV on the encoder...
// I should add a convenience function for this:
val encoder = SpritzCipher.cipherStream("some password")
encoder.absorbStop()
encoder.absorb(my_iv)
encoder.squeezeXOR(my_data)
```

[1]: http://people.csail.mit.edu/rivest/pubs/RS14.pdf
