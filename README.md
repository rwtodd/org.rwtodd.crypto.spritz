# Spritz #

It's just a tool to play with hashes and encryption via the
[spritz cipher][1].

This version should work on a recent UNIX.  It uses autotools, so the
typical `configure && make check && make install` will work as expected.

In this repository, there
is a branch `other-impls` with lots of implementations of the
algorithm in different languages.  The hashes between all
implementations should agree, but the encrypted files tend to use
slightly different formats and keygen strategies.  Also, I have a
[Go.Spritz repo][2] with pretty full-featured tool in Go.

## Usage Examples ##

```bash
# print 256-bit, base64 hashes of all the c files
spritz hash *.c

# now use 32-bit hashes and print in hex 
spritz hash -h -s 32 *.c

# make an encrypted package of all the c files
tar cf - *.c | spritz crypt > out.tar.spritz

# decrypt the c files
spritz crypt -d out.tar.spritz | tar xf -

# check that you know the password on an encrypted file
spritz crypt -n out.tar.spritz

# re-key an encrypted file with a different password, in-place
spritz rekey out.tar.spritz
```

[1]: http://people.csail.mit.edu/rivest/pubs/RS14.pdf
[2]: https://github.com/rwtodd/Go.Spritz/
