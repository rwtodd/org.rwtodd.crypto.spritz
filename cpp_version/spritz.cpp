/* let's make a quick c-version of
 * the hasher, and see how it compares
 * to the other versions, speed-wise.
 */

#include "spritz.hpp"
#include<cstddef>

spritz::cipher::cipher() : 
   i {0}, j{0}, k{0}, z{0}, a{0}, w{1} {
  for(int idx = 0; idx < 256; ++idx) {
     mem[idx] = idx;
  }
}

static inline void swap(uint8_t* const arr, 
                        const std::size_t el1, 
                        const std::size_t el2) {
  uint8_t tmp = arr[el1];
  arr[el1] = arr[el2];
  arr[el2] = tmp;
}

/* when adding indices... need to clip them at 256 */
#define clip_mem(x)  mem[ (x) & 0xff ]

void spritz::cipher::update(int times) {
  uint8_t mi = i;
  uint8_t mj = j;
  uint8_t mk = k;
  const uint8_t mw = w ;
  
  while(times--) {
    mi += mw;
    mj = mk + clip_mem(mj+mem[mi]);
    mk = mi + mk + mem[mj];
    swap(mem, mi, mj);
  }
 
  i = mi;
  j = mj;
  k = mk;
}

static int gcd(const int e1, const int e2) {
  if(e2 == 0) return e1;
  return gcd(e2, e1%e2);
}

void spritz::cipher::whip(const int amt) {
  update(amt);
  do {
    w++;
  } while(gcd(w, 256) != 1);
}


void spritz::cipher::crush() {
  for(std::size_t v = 0; v < 128; ++v) {
    if(mem[v] > mem[255-v]) swap(mem,v,255-v);
  }
}

void spritz::cipher::shuffle() {
  whip(512); crush();
  whip(512); crush();
  whip(512);
  a = 0;
}

inline void spritz::cipher::absorb_nibble(const uint8_t x) {
  if(a == 128) shuffle(); 
  swap(mem, a, (128+x));
  a++;
}

void spritz::cipher::absorb(const uint8_t b) {
  absorb_nibble(b&0x0f);
  absorb_nibble(b>>4);
}

void spritz::cipher::absorb_stop() {
  if(a == 128) shuffle();
  a++;
}

uint8_t spritz::cipher::drip() {
  if(a > 0) shuffle();
  update(1);
  z = clip_mem(j + clip_mem(i + clip_mem(z + k)));
  return z;
}

