package main

import (
	"fmt"
	"io"
	"os"
)

const (
	N = 256
)

type SpritzState struct {
	i, j, k, z, a, w byte
	s                [N]byte
}

func CreateSpritz() *SpritzState {
	ans := &SpritzState{w: 1}
	for i := range ans.s {
		ans.s[i] = byte(i)
	}
	return ans
}

func Absorb(ss *SpritzState, b byte) {
	absorbNibble(ss, b&0x0F)
	absorbNibble(ss, b>>4)
}

func AbsorbMany(ss *SpritzState, bs []byte) {
	for _, b := range bs {
		absorbNibble(ss, b&0x0F)
		absorbNibble(ss, b>>4)
	}
}

func swap(arr *[N]byte, e1 int, e2 int) {
    arr[e1],arr[e2] = arr[e2],arr[e1]
}

func absorbNibble(ss *SpritzState, x byte) {
	if ss.a == N/2 {
		shuffle(ss)
	}
	swap(&ss.s, int(ss.a), int(N/2+x))
	ss.a++
}

func AbsorbStop(ss *SpritzState) {
	if ss.a == N/2 {
		shuffle(ss)
	}
	ss.a++
}

func gcd(e1 int, e2 int) int {
	if e2 == 0 {
		return e1
	}
	return gcd(e2, e1%e2)
}

func whip(ss *SpritzState, amt int) {
	for i := 0; i < amt; i++ {
		update(ss)
	}
	ss.w++
	for gcd(int(ss.w), 256) != 1 {
		ss.w++
	}
}

func crush(ss *SpritzState) {
	for v := 0; v < (N / 2); v++ {
		if ss.s[v] > ss.s[N-1-v] {
			swap(&ss.s, v, N-1-v)
		}
	}
}

func shuffle(ss *SpritzState) {
	whip(ss, N*2)
	crush(ss)
	whip(ss, N*2)
	crush(ss)
	whip(ss, N*2)
	ss.a = 0
}

func update(ss *SpritzState) {
	ss.i += ss.w
	ss.j = ss.k + ss.s[ss.j+ss.s[ss.i]]
	ss.k = ss.i + ss.k + ss.s[ss.j]
	ss.s[ss.i], ss.s[ss.j] = ss.s[ss.j], ss.s[ss.i]
}

func Drip(ss *SpritzState) byte {
	if ss.a > 0 {
		shuffle(ss)
	}
	update(ss)
	ss.z = ss.s[ss.j+ss.s[ss.i+ss.s[ss.z+ss.k]]]
	return ss.z
}

func DripMany(ss *SpritzState, bs []byte) {
	for idx := range bs {
		bs[idx] = Drip(ss)
	}
}

func Hash(bits int, strm io.Reader) []byte {
	bytes := (bits + 7) / 8
	ans := make([]byte, bytes)
	ss := CreateSpritz()

	buffer := make([]byte, 4096)
	count, err := strm.Read(buffer)
	for count >= 0 && err != io.EOF {
		AbsorbMany(ss, buffer[:count])
		count, err = strm.Read(buffer)
	}

	AbsorbStop(ss)
	Absorb(ss, byte(bytes))

	DripMany(ss, ans)
	return ans
}

func main() {
	for _, fname := range os.Args[1:] {
		fmt.Printf("%s: ", fname)
		infile, _ := os.Open(fname)
		hash := Hash(256, infile)
		infile.Close()
		for _, v := range hash {
			fmt.Printf("%02x", v)
		}
		fmt.Println("")
	}
}
