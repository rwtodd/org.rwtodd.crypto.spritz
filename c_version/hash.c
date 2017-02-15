#include "spritz.h"
#include<stdbool.h>
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>


/* *************************************************************
 * G L O B A L   F L A G S
 * *************************************************************
 */

/* we have the option of base64-encoding the hashed output... see b64.c */
char *base64_encode(const uint8_t * in, size_t len);
bool use_b64;  

/* record the hash size in bytes as a program-wide flag */
size_t hash_size; 


/* *************************************************************
 * U T I L I T Y   F U N C S 
 * *************************************************************
 */

/* print_hash: prints a given hash as a series of bytes */
static void print_hash(const uint8_t * const h)
{
    if(use_b64) {
      char *const encoded = base64_encode(h, hash_size);
      fputs(encoded, stdout);
      free(encoded);
    } else {
      /* just print hex */
      for (size_t i = 0; i < hash_size; ++i) {
  	  printf("%02x", h[i]);
      }
   }
}

/* maybe_open: A wrapper for open().  If the filename isnt "-", open 
 * filename. Otherwise, return 0 (stdin) of 1 (stdout) based on the 
 * 'flags`.
 */
static int maybe_open(const char *const fname, int flags, mode_t mode)
{
    int reading = (flags == O_RDONLY);
    if (!strcmp(fname, "-")) {
	return reading ? 0 : 1;	/* stdin:stdout */
    }

    return reading ? open(fname, flags) : open(fname, flags, mode);
}


/* *************************************************************
 * M A I N   P R O G R A M   
 * *************************************************************
 */


/* hash_fname: conpute the hash, size 'sz', of the file 'fname' */
static int hash_fname(const char *const fname)
{
    int fd = maybe_open(fname, O_RDONLY, 0);
    if (fd < 0) {
	fprintf(stderr, "ERROR Could not open <%s>\n", fname);
	return fd;
    }

    const uint8_t *const hash = spritz_file_hash(fd, hash_size);
    close(fd);

    if (hash == NULL) {
	fprintf(stderr, "ERROR Could not hash <%s>\n", fname);
	return -1;
    }

    printf("%s: ", fname);
    print_hash(hash);
    putchar('\n');

    destroy_spritz_hash(hash);
    return 0;
}

int main(int argc, char **argv)
{
    /* parse cmdline args */
    int c;
    hash_size = 32;
    use_b64 = true; /* assume we'll use base64 by default */

    while ((c = getopt(argc, argv, "hs:")) != -1) {
	switch (c) {
	case 'h':
            use_b64 = false;
	    break;
	case 's':
	    hash_size = (atoi(optarg) + 7) / 8;
	    if (hash_size < 1)
		hash_size = 1;
	    break;
	}
    }

    /* run the hashes */
    int err = 0;		/* track errors */
    if (optind >= argc) {
	err += hash_fname("-");
    } else {
	for (int idx = optind; idx < argc; ++idx) {
	    err += hash_fname(argv[idx]);
	}
    }
    return (err < 0);
}
