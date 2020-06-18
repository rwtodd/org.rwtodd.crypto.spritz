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
size_t base64_outsize (size_t insize);
void base64_encode (const uint8_t * in, size_t len, char *result);
static bool use_b64;

/* record the hash as a program-wide global */
static size_t hash_size;        /* size of the expected hash, in bytes */
static uint8_t *hash;           /* buffer for the hash bytes */
static char *out_buffer;        /* buffer (realloc-able) for output */

/* *************************************************************
 * U T I L I T Y   F U N C S 
 * *************************************************************
 */

/* print_hash: prints a given hash as a series of bytes */
static void
print_hash (const uint8_t * const h)
{
  if (use_b64)
    {
      base64_encode (h, hash_size, out_buffer);
      fputs (out_buffer, stdout);
    }
  else
    {
      /* just print hex */
      for (size_t i = 0; i < hash_size; ++i)
        {
          printf ("%02x", h[i]);
        }
    }
}

/* maybe_open: A wrapper for open().  If the filename isnt "-", open 
 * filename. Otherwise, return 0 (stdin) of 1 (stdout) based on the 
 * 'flags`.
 */
static int
maybe_open (const char *const fname, int flags, mode_t mode)
{
  int reading = (flags == O_RDONLY);
  if (!strcmp (fname, "-"))
    {
      return reading ? 0 : 1;   /* stdin:stdout */
    }

  return reading ? open (fname, flags) : open (fname, flags, mode);
}


/* *************************************************************
 * M A I N   P R O G R A M   
 * *************************************************************
 */


/* hash_fname: conpute the hash, size 'sz', of the file 'fname' */
static bool
hash_fname (const char *const fname)
{
  bool result = false;
  int fd = maybe_open (fname, O_RDONLY, 0);
  if (fd < 0)
    {
      fprintf (stderr, "ERROR Could not open <%s>\n", fname);
      return result;
    }

  if (spritz_file_hash (fd, hash, hash_size))
    {
      printf ("%s: ", fname);
      print_hash (hash);
      putchar ('\n');
      result = true;
    }
  else
    fprintf (stderr, "ERROR Could not hash <%s>\n", fname);

  close (fd);
  return result;
}

int
main (int argc, char **argv)
{
  /* parse cmdline args */
  int c;
  hash_size = 32;
  use_b64 = true;               /* assume we'll use base64 by default */

  while ((c = getopt (argc, argv, "hs:")) != -1)
    {
      switch (c)
        {
        case 'h':
          use_b64 = false;
          break;
        case 's':
          hash_size = (atoi (optarg) + 7) / 8;
          if (hash_size < 1)
            hash_size = 1;
          break;
        }
    }

  /* run the hashes */
  hash = malloc (hash_size * sizeof (uint8_t));
  out_buffer = malloc (base64_outsize (hash_size));
  if ((hash == NULL) || (out_buffer == NULL))
    {
      fputs ("Could not allocate buffers!", stderr);
      return 1;
    }

  int err = 0;                  /* track errors */
  if (optind >= argc)
    {
      err += (hash_fname ("-") ? 0 : 1);
    }
  else
    {
      for (int idx = optind; idx < argc; ++idx)
        {
          err += (hash_fname (argv[idx]) ? 0 : 1);
        }
    }
  return (err > 0);
}
