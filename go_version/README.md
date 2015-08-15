# Go Version

For fun, I wrote enough of a golang version to produce the hash
function.  However, when I ran it on a large (100MB) file, it
took twice as long as the scala version to finish.

I was surprised!

Since this was my first go program, I thought maybe some 
golang-specific optimization would help.  But, I ran with the 
`runtime/pprof` tool as described [here][1], and over 80% 
of the time was spent in this function:

```
func update(ss *SpritzState) {
   ss.i += ss.w
   ss.j = ss.k + ss.s[ss.j+ss.s[ss.i]]
   ss.k = ss.i + ss.k + ss.s[ss.j]
   ss.s[ss.i], ss.s[ss.j] = ss.s[ss.j], ss.s[ss.i]
}

```

... which isn't promising, since there isn't much to work with
but a bunch of computations.  I tried pulling the state components
into local variables and working on them, in case the lookup into
`SpritzState` was the issue, but that didn't help.  SpritzState is
just a pointer to a plain struct, anyway.

So, I didn't bother implementing encryption and decryption.

If you build this, you can run it against one or more filenames like so:

```
> ./spritz file1 file2 ...
file1: <<hash>>
file2: <<hash>>

```

[1]: http://blog.golang.org/profiling-go-programs

