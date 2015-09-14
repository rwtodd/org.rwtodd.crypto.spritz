C++ Version
===========

Because I'm a language nut, I decided to adapt the 
c version to c++ and see how much nicer it is with
iterators driving the algorithms.

It does turn out to save some typing, though the
resuling binary is a little bigger.  The speed 
is pretty much identical to the c version.

iostreams are a bit fiddly when it comes to fomatting,
but with google at my side it wasn't a big deal.

What I like about the template/iterator approach is
that the code can automatically accept all kinds of 
inputs.  What I _don't_ like is that it puts a little
more pressure on the user. For instance, if the user
forgets to set `noskipws` on their `istream`,  they
will not get the right answer for hashing.

