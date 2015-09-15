# C Version

I wanted to see how much faster a C version of the hasher would
be, compared to the java version.  Imagine my surprise that the
java version is slightly faster!

I tried turning off the buffering on the `FILE *` in case
that was the problem, but that only slightly changed the
outcome.

My initial try, surprisingly, was slower than the java version.
On a 460MB file, it ran in 79 seconds vs. java's 60 seconds.

However, looking at compiler's assembly output for the innermost loop,
I realized I could make an important optimization.  Here's the 
unoptimized loop:

```
static void update(spritz_state s, int times) {
  while(times--) {
    s->i += s->w;
    s->j = s->k + smem(s->j+s->mem[s->i]);
    s->k = s->i + s->k + s->mem[s->j];
    swap(s->mem, s->i, s->j);
  }
}
```

... and here's the optimized version:

```
static void update(spritz_state s, int times) {
  uint8_t mi = s->i;
  uint8_t mj = s->j;
  uint8_t mk = s->k;
  const uint8_t mw = s->w ;
  
  while(times--) {
    mi += mw;
    mj = mk + smem(mj+s->mem[mi]);
    mk = mi + mk + s->mem[mj];
    swap(s->mem, mi, mj);
  }
 
  s->i = mi;
  s->j = mj;
  s->k = mk;
}
```

In the optimized version, I'm helping the compiler to see that it
doesn't need to store the intermediate values of `i`, `j`, and `k`
back into the state structure until it's done with all the iterations.

With that change, the C version takes 54 seconds against java's 60. Still
not a big win for C... and I chalk that up to my naive use of `fread`
vs. java's probably much more optimized I/O.  

