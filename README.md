# spritz cipher

In this repository, you will find several implementations of
the spritz cipher (described [in RS14.pdf][1]).  Every implementation
is sufficient to compute a hash of file contents, and some of them
can also encrypt and decrypt files.

The three most mature implementations are:

  * __C__: This is the fastest implementation.  It has gone through
  a number of iterations, you can see in the repo history.  Currently,
  it uses a perl wrapper to provide concurrency when needed.  In the
  past, it did the `fork()/poll()` process pool itself, but the 
  wrapper script makes all the individual pieces simpler.

  * __Go__: The go implementation in this repo is just a hasher, but
  I have a full-featured implementation for both the hash and the
  encryption cipher in [my spritz_go repo][2]. The one here was
  just a speed test/prototype.  It processes the files concurrently,
  of course!

  * __Java__: Java was the second impementation I did, and it has a
  hasher and encryptor. It uses JKD8 streams and the fork/join pool
  for concurrency.  It provides the encryption/decryption as stream
  wrappers, which is very nice.

The rest of the implementations--mostly just hashers--are mainly written 
to compare the way they look, how hard they were to write, and
how fast the resulting programs run.

  * __scala__: Scala was the first implementation, when I was
  briefly in love with the language and looking for projects
  to try it out on.  This has a hasher and encryptor, but I didn't
  make these concurrent.  It's interesting to compare it to the
  java version, since `val x` is so much more compact than `final int x`.
  This was some of my first scala code, and I'm sure it has many
  warts.

  * __Forth__: Like all forth, it's a compact, fun program, and a 
  labor of love.  Depending on which forth you run it on, it is 
  respectably fast.

  * __F#__: I was very impressed with how tiny the program came out.
  This is one of a handful of F# programs I've written, and they
  all remind me of O'Caml.  It uses parallel streams for concurrency.

  * __C++__: This hasher was built from a version of the C code. I
  was pleased with how small I could make the public surface of the
  class, and also how templates+iterators enabled the user to hash
  just about any sequence they could dream up.  There really is
  something to be said for the STL design. However, the prospect
  of trying to build encryption into a custom `istream` or `ostream`
  makes my stomach turn. `iostreams` are an unfortunate mistake in
  C++'s history.

There are README files in the subdirectories with a little more information

about each implementation.
[1]: http://people.csail.mit.edu/rivest/pubs/RS14.pdf
[2]: https://github.com/waywardcode/spritz_go
