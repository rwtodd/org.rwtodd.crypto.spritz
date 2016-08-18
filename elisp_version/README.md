# Spritz Cipher in Emacs

You definitely want to byte-compile this one, as it's on the slow side otherwise!


## Main Functions Provided

There are three interactive functions at present:

  *  `spritz-hash` will ask you for a filename, hash it, and insert the filename and hash 
     into the current buffer.  If you give a (`C-u`) numeric argument, that will be the 
     size of the hash in bits.  Default is 256-bit hash.
  *  `spritz-encrypt` takes the current buffer and writes it out encrypted, with the given
     filename and password
  *  `spritz-decrypt` takes a filename and password, and decrypts a file into a new buffer.

## Multibyte Characters

I think as long as we assume you want to use the elisp version for text files, I have 
successfully managed to round-trip UTF-8 characters without munging them.  It's harder
than it seems like it should be!

On the output/encryption side, I take the buffer's contents and call `string-as-unibyte` on
it.  I'm careful to output to a unibyte temp buffer, and then write it out witn `binary` 
encoding.

On the input/decryption side, I load the encrypted file into a unibyte temp buffer, grab 
the buffer's string, then write decrypted bytes into *another* temp unibyte buffer.  Finally,
I call `string-as-multibyte` on the result and insert it into a fresh regular buffer. 

That's a *lot* more copies of the contents than I expected to need on decryption, and
perhaps an elisp master could do better.  What I have seems to work, and any encrypted
notes I make are going to be so short I won't care anyway.  It's just nice to have
support in emacs for reading and writing spritz files without plain-text going to disk.

## V2 file format

The default key generation on the other implementations (scala, go, etc.) runs 5000 rounds
of hashing on the key, but the best elisp I could write spins for like 6 or 7 seconds doing
that.  It's really not a good experience, especially since I think all of those iterations
aren't buying much security.

So, I upped the version number on the save format to 2, and only do 500 rounds of hashing
on v2 files.  The elisp code can read v1 or v2 files, but I only make it write v2 files.
At some point I may update the other implementations to understand the v1/v2 difference.

## Alternte Implementation Idea

An alternate (or even, supplementary) method would be to call out to a spritz binary
(say, the Go version) and pipe the contents through it.  I like the self-contained
elisp, but having it call out to a faster binary if it can find one might make sense
as a future upgrade.

