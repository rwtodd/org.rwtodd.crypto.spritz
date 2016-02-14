/* let's make a quick c-version of
 * the hasher, and see how it compares
 * to the other versions, speed-wise.
 */

#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

static void print_hash(size_t bytes, const uint8_t*const hash) {
  for(size_t v = 0; v < bytes; ++v) {
     printf("%02x",hash[v]);
  } 
}

static void usage() {
  fprintf(stderr,"Usage: spritz-hash [options] file1 file2...\n");
  fprintf(stderr,"  -h    Display this help message.\n");
  fprintf(stderr,"  -s n  Set the hash size to n bits\n");
  fprintf(stderr,"  -j n  Run n hashes at once.\n");
  exit(2);
}

int main(int argc, char **argv) {
  int c;
  int sz = 32;
  int jobs = 1;

  while ( (c = getopt(argc,argv,"hs:j:")) != -1 ) {
     switch(c) {
     case 'h':
	usage();
	break;
     case 'j':
        jobs = atoi(optarg);
        if(jobs < 1) jobs = 1;
	break;
     case 's':
        sz = (atoi(optarg) + 7) / 8;
        if(sz < 1) sz = 1;
	break;
     } 
  }

  if(argc <= optind) { usage(); }
  int nerr = 0;
  for(int idx = optind; idx < argc; ++idx) {
     printf("%s: ",argv[idx]);
     FILE *input = fopen(argv[idx],"rb");
     setvbuf(input, 0, _IONBF, 0);
     if(input != NULL) {
       const uint8_t *const hash = spritz_file_hash(sz,input);
       fclose(input);

       if(hash == NULL) {
          ++nerr;
          fprintf(stderr,"error!\n");
	  continue;
       }

       print_hash(sz,hash);
       printf("\n");
       destroy_spritz_hash(hash);
     } else {
       fprintf(stderr,"BAD FILE\n");
       ++nerr;
     }
  }

  return (nerr==0)?0:1;
}
