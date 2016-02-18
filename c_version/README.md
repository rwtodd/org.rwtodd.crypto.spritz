# C Version

## (2016-02-14) Concurrency Via Fork()

I wanted to see how a concurrent model based on fork would compare
with my [go version in the other repo](https://github.com/waywardcode/spritz_go).
So, tonight I added a `-j` option to the c hasher like _make_ has for 
how many concurrent jobs to spin up.  I defined a simple
language for the worker processes to communicate back up the parent (via pipes):

    "OK <msg>" ==> print the msg to stdout and give me more work 
    "ER <msg>" ==> print this error message, and give me more work

The results, hashing 1.6GB of files took:

    time:   50s for the c version with 8 jobs (-j8)
    time: 1m23s for the Go version (max procs = 8)

So, the c version is a good bit faster, but I had to work _a lot_ harder at the
concurrency.  I had to:

  * manually fork off the processes, create the pipes, and hook them up.
  * devise a protocol for them to speak to each other
  * implement the protocol, including all the necessary error-handling
    and buffering

Meanwhile, in Go, converting the serial version to the concurrent version just took a couple
lines of code. So, on any given project, you have to decide how much performance you are 
willing to trade for convenience. 

## Original Implementation Notes

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

