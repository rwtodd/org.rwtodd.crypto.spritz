# C Version

I wanted to see how much faster a C version of the hasher would
be, compared to the java version.  Imagine my surprise that the
java version is slightly faster!

I tried turning off the buffering on the `FILE *` in case
that was the problem, but that only slightly changed the
outcome.

When hashing a 22MB file, the java version takes 2.78s, and the
C version takes 3.82s.  I'm a little surprised, since there's
really not a lot for me to "screw up" about the C implementation.
It only allocates once, at the start of the hashing process. The
rest is just file reads and computation.

So... just as with the `go` implementation, I didn't bother pushing
forward to do the encrypter/decrypter.

Java FTW?  I guess...

(the tests were run on OS X Yosemite)

_Edit: 2015-08-26_: I ran the tests again on a Windows 10 laptop, 
and java still edges out C here.  (4.6s vs 5.1s on the same
file as the OS X test).

