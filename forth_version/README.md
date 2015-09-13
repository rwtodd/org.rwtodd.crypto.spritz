Forth Version
=============

I couldn't help myself... I made a forth version
of the hash function to compare it.

On a large file, the java version took ~2.5 seconds,
and with gforth-fast, I got ~12 seconds. So about 4.8x 
slower than the java version.

_Edit: 2015-09-13_ I compiled and tested against MPE VFX Forth
and the test ran in 3.5 seconds. So that's about 1.4x
slower than the java version.  Much more respectable.

Though I personally really enjoyed
developing this version, I had to spend a couple hours
optimizing it to get it close to the java speed.  That's
probably something most people aren't going to want
to do on a regular basis.

```
S" FILENAME.EXT" PAD 32 file-hash   PAD 32 print-hash
( ... output ommitted ... ) ok

( here's one of the tests from the RS14.pdf )
S" ABC" PAD 32 string-hash   PAD 32 cr print-hash
028FA2B48B934A1862B86910513A47677C1C2D95EC3E7570786F1C328BBD4A47 ok
```
