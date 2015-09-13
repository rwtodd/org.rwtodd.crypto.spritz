/* let's make a quick c-version of
 * the hasher, and see how it compares
 * to the other versions, speed-wise.
 */

#include "spritz.h"
#include<stdint.h>
#include<stdio.h>

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
       const uint8_t *const hash = spritz_file_hash(32,input);
       fclose(input);
       print_hash(32,hash);
       printf("\n");
       destroy_spritz_hash(hash);
     } else {
       printf("BAD FILE\n");
     }
  }

  return 0;
}
