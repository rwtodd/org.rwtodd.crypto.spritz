/* let's make a quick c-version of
 * the hasher, and see how it compares
 * to the other versions, speed-wise.
 */

#include "spritz.h"
#include<stdlib.h>

#define N 256

struct s_spritz_state {
	uint8_t i, j, k, z, a, w; 
	uint8_t mem[N];
};

/* creates memory that should be destroyed by
 * call to destroy_spritz
 */
spritz_state create_spritz(void) {
  spritz_state ans = malloc(sizeof(struct s_spritz_state));
  ans->i = ans->j = ans->k = ans->z = ans->a = 0;
  ans->w = 1;
  for(int idx = 0; idx < N; ++idx) {
     ans->mem[idx] = idx;
  }
  return ans;
}

void destroy_spritz(spritz_state s) {
  free(s);
}

static inline void swap(uint8_t *const arr, size_t el1, size_t el2) {
  uint8_t tmp = arr[el1];
  arr[el1] = arr[el2];
  arr[el2] = tmp;
}

/* when adding indices... need to clip them at 256 */
#define smem(x)  s->mem[ (x) & 0xff ]

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

static int gcd(const int e1, const int e2) {
  if(e2 == 0) return e1;
  return gcd(e2, e1%e2);
}

static void whip(spritz_state s, const int amt) {
  update(s,amt);
  do {
    s->w++;
  } while(gcd(s->w, N) != 1);
}


static void crush(spritz_state s) {
  for(size_t v = 0; v < (N/2); ++v) {
    if(s->mem[v] > s->mem[N-1-v]) swap(s->mem,v,N-1-v);
  }
}

static void shuffle(spritz_state s) {
  whip(s, N*2);
  crush(s);
  whip(s, N*2);
  crush(s);
  whip(s, N*2);
  s->a = 0;
}

static inline void absorb_nibble(spritz_state s, uint8_t x) {
  if(s->a == N/2) shuffle(s); 
  swap(s->mem, s->a, (N/2+x));
  s->a++;
}

void spritz_absorb(spritz_state s, const uint8_t b) {
  absorb_nibble(s, b&0x0f);
  absorb_nibble(s, b>>4);
}

void spritz_absorb_many(spritz_state s, const uint8_t* bytes, size_t len) {
  const uint8_t*const end = bytes+len;
  while(bytes != end) {
     spritz_absorb(s,*bytes++); 
  } 
}


void spritz_absorb_stop(spritz_state s) {
  if(s->a == N/2) shuffle(s);
  s->a++;
}

static uint8_t drip_one(spritz_state s) {
  update(s,1);
  s->z = smem(s->j + smem(s->i + smem(s->z + s->k)));
  return s->z;
}

uint8_t spritz_drip(spritz_state s) {
  if(s->a > 0) shuffle(s);
  return drip_one(s);
}

void spritz_drip_many(spritz_state s, uint8_t* arr, size_t len) {
   uint8_t *const end = arr + len;
   if(s->a > 0) shuffle(s);
   while(arr != end) {
      *arr++ = drip_one(s);
   }
}

/* returns a hash which must be destroyed by 
 * destroy_hash. 
 */
uint8_t* spritz_file_hash(uint8_t bytes, FILE *input) {
   uint8_t *const ans = malloc(bytes*sizeof(uint8_t));
   uint8_t *const buffer = malloc(4096*sizeof(uint8_t));
   spritz_state s = create_spritz();
  
   size_t num_read; 
   while((num_read = fread(buffer, sizeof(uint8_t), 4096, input)) > 0) {
      spritz_absorb_many(s, buffer, num_read);
   }
   if(!feof(input)) { fprintf(stderr,"Problem reading the file!");  }

   spritz_absorb_stop(s);
   spritz_absorb(s, bytes);
   spritz_drip_many(s,ans,bytes);
   destroy_spritz(s);   
   free(buffer);
   return ans;
} 

/* returns a hash which must be destroyed by 
 * destroy_hash. 
 */
uint8_t* spritz_string_hash(uint8_t bytes, 
                            const uint8_t * const str, 
                            size_t len) {
   uint8_t *const ans = malloc(bytes*sizeof(uint8_t));
   spritz_state s = create_spritz();

   spritz_absorb_many(s,str,len);
   spritz_absorb_stop(s);
   spritz_absorb(s, bytes);

   spritz_drip_many(s,ans,bytes);
   destroy_spritz(s);   
   return ans;
} 

void destroy_spritz_hash(const uint8_t*const hash) {
  free((void*)hash);
}

