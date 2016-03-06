#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<time.h>


/* generate bytes of random data */
static void gen_rdata(uint8_t * buf, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
	buf[i] = rand() & 0xff;;
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

/* processor, the type that can either be an encryptor or decryptor */
typedef int (*processor) (const uint8_t * const pw_hash, const char *src,
			  const char *tgt);

/* decrypt_file: decrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static int decrypt_file(const uint8_t * const pw_hash, const char *src,
			const char *tgt)
{
    int result = -1;
    uint8_t buf[12];		/* IV, random data, hash of random data */

    int srcfd = -1, tgtfd = -1;
    uint8_t *rhash = NULL;

    if ((srcfd = maybe_open(src, O_RDONLY, 0)) < 0 ||
	(tgtfd =
	 maybe_open(tgt, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
	fprintf(stderr, "%s error: Failed to open input or output file!\n",
		src);
	goto cleanup;
    }

    /* read the IV, rdata, and hashed rdata */
    if (read(srcfd, buf, 12) != 12) {
	fprintf(stderr, "%s Can't read IV!\n", src);
	goto cleanup;
    }

    /* now decrypt the random data and its hash... */
    spritz_state ss = spritz_crypt(pw_hash, 32, buf, 4);
    spritz_xor_many(ss, buf + 4, 8);
    if ((rhash = spritz_mem_hash(buf + 4, 4, 4)) == NULL) {
	fprintf(stderr, "%s error: Can't hash!\n", src);
	goto cleanup2;
    }

    if (memcmp(rhash, buf + 8, 4) != 0) {
	fprintf(stderr, "%s: Bad password or corrupt file!\n", src);
	goto cleanup2;
    }

    /* ok, looks like the password was right... now decrypt */
    if (spritz_xor_copy(ss, tgtfd, srcfd) < 0) {
	fprintf(stderr, "%s: Decryption error!\n", src);
	goto cleanup2;
    }

    /* no errors! */
    result = 0;
    if (tgtfd != 1)
	printf("%s -decrypt-> %s\n", src, tgt);

  cleanup2:
    if (ss != NULL)
	destroy_spritz(ss);
  cleanup:
    if (rhash != NULL)
	destroy_spritz_hash(rhash);
    if (tgtfd >= 0)
	close(tgtfd);
    if (srcfd >= 0)
	close(srcfd);
    return result;
}


/* encrypt_file: encrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static int encrypt_file(const uint8_t * const pw_hash, const char *src,
			const char *tgt)
{
    int result = 1;
    uint8_t buf[12];		/* IV, random data, hash of random data */
    int srcfd = -1, tgtfd = -1;

    gen_rdata(buf, 8);

    uint8_t *rhash = NULL;
    if ((rhash = spritz_mem_hash(buf + 4, 4, 4)) == NULL) {
	fprintf(stderr, "%s error: Can't hash!\n", src);
	goto cleanup;
    }

    memcpy(buf + 8, rhash, 4);
    destroy_spritz_hash(rhash);

    if ((srcfd = maybe_open(src, O_RDONLY, 0)) < 0 ||
	(tgtfd =
	 maybe_open(tgt, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
	fprintf(stderr, "%s error: Failed to open input or output file!\n",
		src);
	goto cleanup;
    }

    /* now encrypt and write out the file... */
    spritz_state ss = spritz_crypt(pw_hash, 32, buf, 4);
    spritz_xor_many(ss, buf + 4, 8);
    if (write(tgtfd, buf, 12) != 12 ||
	spritz_xor_copy(ss, tgtfd, srcfd) < 0) {
	fprintf(stderr, "%s error: Failed to write!\n", tgt);
	goto cleanup2;
    }

    /* no errors! */
    result = 0;
    if (tgtfd != 1)
	printf("%s -encrypt-> %s\n", src, tgt);

  cleanup2:
    if (ss != NULL)
	destroy_spritz(ss);
  cleanup:
    if (tgtfd >= 0)
	close(tgtfd);
    if (srcfd >= 0)
	close(srcfd);
    return result;
}

static void usage()
{
    fprintf(stderr, "Usage: spritz-crypt [options] [file1 file2...]\n");
    fprintf(stderr, "  -d      Decrypt the input files.\n");
    fprintf(stderr, "  -h      Display this help message.\n");
    fprintf(stderr, "  -o dir  Put the output files in dir.\n");
    fprintf(stderr, "  -p pwd  Set the password to use.\n");
    exit(2);
}

/* basename: from path 'src', return the basename
 * as a pointer into the same memory as 'src'
 */
static const char *basename(const char *src)
{
    const char *bn = strrchr(src, '/');
    if (bn == NULL)
	bn = src;
    else
	++bn;			/* go past the '/' we found */
    return bn;
}

/* determine_target: allocates and creates a target filename from
 * the 'src' filename, an output directory 'odir', and a flag telling
 * whether we are 'encrypting' or not.
 */
static char *determine_target(int encrypting, const char *odir,
			      const char *src)
{
    static const char *extension = ".spritz";
    static const char *unenc = ".unenc";
    char *tgt = NULL;		/* the target filename */
    size_t tgtlen = 0;		/* the needed length of tgt */
    size_t odirlen = 0;
    size_t srclen = 0;

    /* First, determine the max space needed */
    if (odir != NULL) {
	odirlen = strlen(odir);
	src = basename(src);
    }

    /* just get 7 extra characters, in case we 
     * need to add a suffix, plus another for
     * the '\0'
     */
    srclen = strlen(src);
    tgtlen = odirlen + srclen + 7 + 1;

    /* Second, allocate and copy the filename */
    if ((tgt = malloc(tgtlen * sizeof(char))) == NULL) {
	fprintf(stderr, "%s: failed to allocate memory!\n", src);
	return NULL;
    }

    char *loc = tgt;
    if (odir != NULL) {
	strcpy(loc, odir);
	loc += odirlen;
    }
    strcpy(loc, src);
    loc += srclen;

    /* Third, determine the suffix */
    if (encrypting) {
	/* encrypting: add spritz */
	strcpy(loc, extension);
    } else {
	/* decrypting: remove a ".spritz" ending, if it's there */
	if ((loc - tgt > 7) && (!strcmp(loc - 7, extension))) {
	    *(loc - 7) = '\0';
	} else {
	    strcpy(loc, unenc);
	}
    }

    return tgt;
}


/* collect_password opens /dev/tty and speaks
 * directly to the user, asking for a password.
 * This way, it will work even when the program
 * is processing stdin.
 */
uint8_t* collect_password(void)
{
  char pwbuff[256];
  uint8_t * pw_hash = NULL;
  size_t len = 0;
  FILE *tty;

  memset(pwbuff,0, sizeof(pwbuff));

  if( (tty = fopen("/dev/tty", "r+")) == NULL ) {
     fputs("Couldn't open tty!\n", stderr);
     return NULL;
  } 

  fputs("Password: ", tty);
  fflush(tty);
  if(fgets(pwbuff, sizeof(pwbuff), tty) == NULL) {
     fputs("Error reading pw!\n", stderr); 
  }

  fclose(tty);

  len = strlen(pwbuff);
  if(len <= 1) {
	fputs("Error collecting password!\n",stderr);
	return NULL;
  }

  if(pwbuff[len-1] == '\n')
     pwbuff[--len] == '\0';

  return spritz_mem_hash(pwbuff, len, 32);
}


int main(int argc, char **argv)
{
    /* parse cmdline args */
    int c;
    size_t len;			/* for counting strings during argument parsing */
    processor proc = encrypt_file;	/* assume we are encrypting */
    char *odir = NULL;		/* the output directory */
    uint8_t *pw_hash = NULL;	/* the hashed password */

    while ((c = getopt(argc, argv, "dho:p:")) != -1) {
	switch (c) {
	case 'd':
	    proc = decrypt_file;
	    break;
	case 'h':
	    usage();
	    break;
	case 'o':
	    if (odir != NULL) {
		fputs("Multiple -o arguments not allowed!\n", stderr);
		exit(1);
	    }
	    len = strlen(optarg);
	    if (len >= 256) {
		fputs("-o argument too long!\n", stderr);
		exit(1);
	    }
	    odir = malloc((len + 2) * sizeof(char));	/* +2 for '/', '\0' */
	    if (odir == NULL) {
		fputs("No memory!\n", stderr);
		exit(1);
	    }
	    strcpy(odir, optarg);
	    if (odir[len - 1] != '/') {
		/* add a final slash if needed */
		odir[len] = '/';
		odir[len + 1] = '\0';
	    }
	    break;
	case 'p':
	    if (pw_hash != NULL) {
		fputs("Multiple -p arguments not allowed!\n", stderr);
		exit(1);
	    }
	    len = strlen(optarg);
	    pw_hash = spritz_mem_hash((const uint8_t *) optarg, len, 32);
	    break;
	}
    }

    /* if we didn't get a password on the command line, ask for it
     * on the terminal
     */
    if (pw_hash == NULL) {
	pw_hash = collect_password();
    }

    srand(time(NULL));

    /* process the files, or stdin */
    int err = 0;
    if ((optind >= argc) ||
	((argc - optind == 1) && (!strcmp(argv[optind], "-")))
	) {
	err += proc(pw_hash, "-", "-");
    } else {
	for (int idx = optind; idx < argc; ++idx) {
	    const char *tgt =
		determine_target(proc == encrypt_file, odir, argv[idx]);
	    if (tgt == NULL) {
		err += -1;
		continue;
	    }
	    err += proc(pw_hash, argv[idx], tgt);
	    free((void *) tgt);
	}
    }

    /* cleanup, although not necessary since we're exiting */
    destroy_spritz_hash(pw_hash);
    free(odir);
    return (err < 0);
}
