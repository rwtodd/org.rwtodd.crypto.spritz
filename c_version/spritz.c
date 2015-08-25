/* let's make a quick c-version of
 * the hasher, and see how it compares
 * to the other versions, speed-wise.
 */

#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>

#define N 256

struct spritz_state {
	uint8_t i, j, k, z, a, w; 
	uint8_t mem[N];
};

typedef struct spritz_state *const state;

/* creates memory that should be destroyed by
 * call to destroy_spritz
 */
state create_spritz(void) {
  state ans = malloc(sizeof(struct spritz_state));
  ans->i = ans->j = ans->k = ans->z = ans->a = 0;
  ans->w = 1;
  for(int idx = 0; idx < N; ++idx) {
     ans->mem[idx] = idx;
  }
  return ans;
}

void destroy_spritz(state s) {
  free(s);
}

static inline void swap(state s, size_t el1, size_t el2) {
  uint8_t *const arr = s->mem;
  uint8_t tmp = arr[el1];
  arr[el1] = arr[el2];
  arr[el2] = tmp;
}

/* when adding indices... need to clip them at 256 */
#define smem(x)  s->mem[ (x) & 0xff ]

static void update(state s) {
  s->i += s->w;
  s->j = s->k + smem(s->j+s->mem[s->i]);
  s->k = s->i + s->k + s->mem[s->j];
  swap(s, s->i, s->j);
}

static int gcd(const int e1, const int e2) {
  if(e2 == 0) return e1;
  return gcd(e2, e1%e2);
}

static void whip(state s, const int amt) {
  for(int ctr = 0; ctr < amt; ++ctr) update(s);
  do {
    s->w++;
  } while(gcd(s->w, N) != 1);
}


static void crush(state s) {
  for(size_t v = 0; v < (N/2); ++v) {
    if(s->mem[v] > s->mem[N-1-v]) swap(s,v,N-1-v);
  }
}

static void shuffle(state s) {
  whip(s, N*2);
  crush(s);
  whip(s, N*2);
  crush(s);
  whip(s, N*2);
  s->a = 0;
}

void absorb_nibble(state s, uint8_t x) {
  if(s->a == N/2) shuffle(s); 
  swap(s, s->a, (N/2+x));
  s->a++;
}

void absorb(state s, const uint8_t b) {
  absorb_nibble(s, b&0x0f);
  absorb_nibble(s, b>>4);
}

void absorb_many(state s, const uint8_t* bytes, size_t len) {
  const uint8_t*const end = bytes+len;
  while(bytes != end) {
     absorb(s,*bytes++); 
  } 
}


void absorb_stop(state s) {
  if(s->a == N/2) shuffle(s);
  s->a++;
}

static uint8_t drip_one(state s) {
  update(s);
  s->z = smem(s->j + smem(s->i + smem(s->z + s->k)));
  return s->z;
}

uint8_t drip(state s) {
  if(s->a > 0) shuffle(s);
  return drip_one(s);
}

void drip_many(state s, uint8_t* arr, size_t len) {
   uint8_t *const end = arr + len;
   if(s->a > 0) shuffle(s);
   while(arr != end) {
      *arr++ = drip_one(s);
   }
}

/* returns a hash which must be destroyed by 
 * destroy_hash. 
 */
uint8_t* file_hash(uint8_t bytes, FILE *input) {
   uint8_t *const ans = malloc(bytes*sizeof(uint8_t));
   uint8_t *const buffer = malloc(4096*sizeof(uint8_t));
   state s = create_spritz();
  
   size_t num_read; 
   while((num_read = fread(buffer, sizeof(uint8_t), 4096, input)) > 0) {
      absorb_many(s, buffer, num_read);
   }
   if(!feof(input)) { fprintf(stderr,"Problem reading the file!");  }

   absorb_stop(s);
   absorb(s, bytes);
   drip_many(s,ans,bytes);
   destroy_spritz(s);   
   free(buffer);
   return ans;
} 

/* returns a hash which must be destroyed by 
 * destroy_hash. 
 */
uint8_t* string_hash(uint8_t bytes, const uint8_t * const str, size_t len) {
   uint8_t *const ans = malloc(bytes*sizeof(uint8_t));
   state s = create_spritz();

   absorb_many(s,str,len);
   absorb_stop(s);
   absorb(s, bytes);

   drip_many(s,ans,bytes);
   destroy_spritz(s);   
   return ans;
} 

void destroy_hash(const uint8_t*const hash) {
  free((void*)hash);
}

static void print_hash(size_t bytes, const uint8_t*const hash) {
  for(size_t v = 0; v < bytes; ++v) {
     printf("%02x",hash[v]);
  } 
}

int main(int argc, char **argv) {
  if(argc < 2) {  fprintf(stderr,"Usage: spritz file1 file2..."); return -1; }
  for(int idx = 1; idx < argc; ++idx) {
     printf("%s: ",argv[idx]);
     FILE *input = fopen(argv[idx],"rb");
     setvbuf(input, 0, _IONBF, 0);
     if(input != NULL) {
       const uint8_t *const hash = file_hash(32,input);
       fclose(input);
       print_hash(32,hash);
       printf("\n");
       destroy_hash(hash);
     } else {
       printf("BAD FILE\n");
     }
  }

  return 0;
}
