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

static inline void print_hash(size_t bytes, const uint8_t * const hash)
{
    for (size_t v = 0; v < bytes; ++v) {
	printf("%02x", hash[v]);
    }
}

static int hash_fd(size_t hash_sz, const char *const fname, int fd)
{
    const uint8_t *const hash = spritz_file_hash(fd, hash_sz);
    close(fd);

    if (hash == NULL) {
	fprintf(stderr, "ERROR Could not hash <%s>\n", fname);
	return 1;
    }

    printf("%s: ", fname);
    print_hash(hash_sz, hash);
    putchar('\n');

    destroy_spritz_hash(hash);
    return 0;			/* no errors */
}

static int hash_fname(size_t hash_sz, const char *const fname)
{
    int input = open(fname, O_RDONLY);
    if (input < 0) {
	fprintf(stderr, "ERROR Could not open <%s>\n", fname);
	return 1;
    }
    return hash_fd(hash_sz, fname, input);
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

    int errcnt = 0;
    if ((optind >= argc) ||
	((argc - optind == 1) && (!strcmp(argv[optind], "-")))
	) {
	errcnt += hash_fd((size_t) sz, "-", 0);
    } else {
	for (int idx = optind; idx < argc; ++idx) {
	    errcnt += hash_fname((size_t) sz, argv[idx]);
	}
    }
    return (errcnt > 0);
}
