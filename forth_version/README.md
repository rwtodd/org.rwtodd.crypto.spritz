Forth Version
=============

I couldn't help myself... I made a forth version
of the hash function to compare it.

On a large file, the java version took ~2.5 seconds,
and with gforth-fast, I got ~12 seconds. So about 4.8x 
slower than the java version.

```
S" FILENAME.EXT" PAD 32 file-hash   PAD 32 print-hash
( ... output ommitted ... ) ok

( here's one of the tests from the RS14.pdf )
S" ABC" PAD 32 string-hash   PAD 32 cr print-hash
028FA2B48B934A1862B86910513A47677C1C2D95EC3E7570786F1C328BBD4A47 ok
```
