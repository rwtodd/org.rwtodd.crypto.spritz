# Spritz

A library and cli implemntation of the [Spritz cipher.](https://people.csail.mit.edu/rivest/pubs/RS14.pdf).

It's not intended for industrial-strength uses, but rather 
as a curiosity. It was an interesting exercise to build out
an encrypted file format that--hopefully--would make it mildly
harder to crack the file even if weaknesses in the cipher were
being attacked.  To give two examples, even the IV is encrypted
by a short hash of the password, and a random number of bytes 
of the cipher stream is skipped and not used in the file at all.
Like some other encryption programs, the file is organized so the
password can be changed *without* re-encrypting the entire file.

I've put it on maven central as 
"org.rwtodd:org.rwtodd.crypto.spritz:1.0.0".

## Other Versions

Other implementations in various languages are available on
[my github](https://github.com/rwtodd).  Some of them are
in different branches of this repository.

