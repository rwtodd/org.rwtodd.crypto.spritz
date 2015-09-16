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

I ran into a similar bottleneck on the C/C++ versions,
and looking at the assembly output I decided I could help
the compiler by looping inside of `update` and taking the 
assignments back into SpritzState out of the loop:

```
func update(ss *SpritzState, amt int) {
	var mi byte = ss.i
	var mj byte = ss.j
	var mk byte = ss.k
	var mw byte = ss.w

	for amt > 0 {
		mi += mw
		smi := ss.s[mi]
		mj = mk + ss.s[mj+smi]
		smj := ss.s[mj]
		mk = mi + mk + smj
		ss.s[mi] = smj
		ss.s[mj] = smi
		amt--
	}

	ss.i = mi
	ss.j = mj
	ss.k = mk
}
```

It's not as pretty, but on the C/C++/golang code it really
helped.  For the golang version, The time on a large file
went from 13.112s to 9.669s.  For comparison, the java
version took 7.424s and the C version took 6.736s on the
same file.

I haven't implemented encryption and decryption cmdline utils
yet.

If you build this, you can run it against one or more filenames like so:

```
> ./spritz file1 file2 ...
file1: <<hash>>
file2: <<hash>>

```

[1]: http://blog.golang.org/profiling-go-programs

