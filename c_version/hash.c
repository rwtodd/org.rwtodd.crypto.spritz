#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>

static void usage()
{
    fprintf(stderr, "Usage: spritz-hash [-s n] [file1 file2..]\n");
    fprintf(stderr, "  -h    Display this help message.\n");
    fprintf(stderr, "  -s n  Set the size of the hash in bits.\n");
    exit(2);
}

/* print_hash: prints a given hash as a series of bytes */
static inline void print_hash(size_t sz, const uint8_t * const h)
{
    for (size_t i = 0; i < sz; ++i) {
	printf("%02x", h[i]);
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

/* hash_fname: conpute the hash, size 'sz', of the file 'fname' */
static int hash_fname(size_t sz, const char *const fname)
{
    int fd = maybe_open(fname, O_RDONLY, 0);
    if (fd < 0) {
	fprintf(stderr, "ERROR Could not open <%s>\n", fname);
	return fd;
    }

    const uint8_t *const hash = spritz_file_hash(fd, sz);
    close(fd);

    if (hash == NULL) {
	fprintf(stderr, "ERROR Could not hash <%s>\n", fname);
	return -1;
    }

    printf("%s: ", fname);
    print_hash(sz, hash);
    putchar('\n');

    destroy_spritz_hash(hash);
    return 0;
}

int main(int argc, char **argv)
{
    /* parse cmdline args */
    int c;
    int sz = 32;

    while ((c = getopt(argc, argv, "hs:")) != -1) {
	switch (c) {
	case 'h':
	    usage();
	    break;
	case 's':
	    sz = (atoi(optarg) + 7) / 8;
	    if (sz < 1)
		sz = 1;
	    break;
	}
    }

    /* run the hashes */
    int err = 0;		/* track errors */
    if (optind >= argc) {
	err += hash_fname((size_t) sz, "-");
    } else {
	for (int idx = optind; idx < argc; ++idx) {
	    err += hash_fname((size_t) sz, argv[idx]);
	}
    }
    return (err < 0);
}
