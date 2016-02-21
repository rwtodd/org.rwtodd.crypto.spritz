/* let's make a quick c-version of
 * the hasher, and see how it compares
 * to the other versions, speed-wise.
 */

#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>

static void usage() {
  fprintf(stderr,"Usage: spritz-hash [-s n]\n");
  fprintf(stderr,"  -h    Display this help message.\n");
  fprintf(stderr,"  -s n  Set the size of the hash in bits.\n");
  exit(2);
}

static inline void print_hash(size_t bytes, const uint8_t*const hash) {
  for(size_t v = 0; v < bytes; ++v) {
     printf("%02x",hash[v]);
  } 
}

static void panic(const char*msg) {
  fputs(msg,stderr);
  exit(1);
}

/* The protocol: 
 *    send "OK %s" --> print to stdout, and I'm ready for more input
 *    send "ER %s" --> print to stderr, and I'm ready for more input
 */
static void run_job(size_t hash_sz) {
     char fname[300];

     if(puts("OK") < 0) panic("Can't write!\n");

     ssize_t len;
     while ( !feof(stdin) ) {
	char *const line = fgets(fname, 300, stdin);
        if(line == NULL) return;

	len = strlen(line);
        /* chop off the newline */
        line[len - 1] = '\0'; 

        int input = open(line,O_RDONLY);
        if(input >= 0) {
          const uint8_t *const hash = spritz_file_hash(input, hash_sz);
          close(input);

          if(hash == NULL) {
            printf("ER Could not hash <%s>\n", fname);
            continue;
          }

	  printf("OK %s: ",line);
          print_hash(hash_sz, hash);
	  putchar('\n');

          destroy_spritz_hash(hash);
        } else {
          printf("ER Could not open <%s>\n",fname);
        }
     }
}

int main(int argc, char **argv) {
  /* parse cmdline args */
  int c;
  int sz = 32;

  if( (setvbuf(stdin, NULL, _IOLBF, 4096) != 0)  ||
      (setvbuf(stdout, NULL, _IOLBF, 4096) != 0) ) {
	fputs("Error setting buffering!\n",stderr);
	return 1;
  }

  while ( (c = getopt(argc,argv,"hs:")) != -1 ) {
     switch(c) {
     case 'h':
	usage();
     	break;
     case 's':
        sz = (atoi(optarg) + 7) / 8;
        if(sz < 1) sz = 1;
        break;
     } 
  }

  run_job(sz);
  return 0;
}
