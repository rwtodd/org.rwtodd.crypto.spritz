#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<time.h>
#include<termios.h>

/* we hash the passwords to 32 bytes */
#define PW_HASH_LEN 32

/* generate bytes of random data */
static void
gen_rdata (uint8_t * buf, size_t len)
{
  for (size_t i = 0; i < len; ++i)
    {
      buf[i] = rand () & 0xff;;
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

/* processor, the type that can either be an encryptor or decryptor */
typedef int (*processor) (const uint8_t * const pw_hash, const char *src,
                          const char *tgt);

/* decrypt_file: decrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static int
decrypt_file (const uint8_t * const pw_hash, const char *src, const char *tgt)
{
  int result = -1;
  uint8_t buf[12];              /* IV, random data, hash of random data */

  int srcfd = -1, tgtfd = -1;

  if ((srcfd = maybe_open (src, O_RDONLY, 0)) < 0 ||
      (tgtfd = maybe_open (tgt, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0)
    {
      fprintf (stderr, "%s error: Failed to open input or output file!\n",
               src);
      goto cleanup;
    }

  /* read the IV, rdata, and hashed rdata */
  if (read (srcfd, buf, 12) != 12)
    {
      fprintf (stderr, "%s Can't read IV!\n", src);
      goto cleanup;
    }

  /* now decrypt the random data and its hash... */
  spritz_state ss = spritz_crypt (pw_hash, PW_HASH_LEN, buf, 4);
  spritz_xor_many (ss, buf + 4, 8);
  uint8_t rhash[4];
  spritz_mem_hash (buf + 4, 4, rhash, 4);

  if (memcmp (rhash, buf + 8, 4) != 0)
    {
      fprintf (stderr, "%s: Bad password or corrupt file!\n", src);
      goto cleanup2;
    }

  /* ok, looks like the password was right... now decrypt */
  if (spritz_xor_copy (ss, tgtfd, srcfd) < 0)
    {
      fprintf (stderr, "%s: Decryption error!\n", src);
      goto cleanup2;
    }

  /* no errors! */
  result = 0;
  if (tgtfd != 1)
    printf ("%s -decrypt-> %s\n", src, tgt);

cleanup2:
  if (ss != NULL)
    destroy_spritz (ss);
cleanup:
  if (tgtfd >= 0)
    close (tgtfd);
  if (srcfd >= 0)
    close (srcfd);
  return result;
}


/* encrypt_file: encrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static int
encrypt_file (const uint8_t * const pw_hash, const char *src, const char *tgt)
{
  int result = 1;
  uint8_t buf[12];              /* IV, random data, hash of random data */
  int srcfd = -1, tgtfd = -1;

  gen_rdata (buf, 8);

  uint8_t rhash[4];
  spritz_mem_hash (buf + 4, 4, rhash, 4);
  memcpy (buf + 8, rhash, 4);

  if ((srcfd = maybe_open (src, O_RDONLY, 0)) < 0 ||
      (tgtfd = maybe_open (tgt, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0)
    {
      fprintf (stderr, "%s error: Failed to open input or output file!\n",
               src);
      goto cleanup;
    }

  /* now encrypt and write out the file... */
  spritz_state ss = spritz_crypt (pw_hash, PW_HASH_LEN, buf, 4);
  spritz_xor_many (ss, buf + 4, 8);
  if (write (tgtfd, buf, 12) != 12 || spritz_xor_copy (ss, tgtfd, srcfd) < 0)
    {
      fprintf (stderr, "%s error: Failed to write!\n", tgt);
      goto cleanup2;
    }

  /* no errors! */
  result = 0;
  if (tgtfd != 1)
    printf ("%s -encrypt-> %s\n", src, tgt);

cleanup2:
  if (ss != NULL)
    destroy_spritz (ss);
cleanup:
  if (tgtfd >= 0)
    close (tgtfd);
  if (srcfd >= 0)
    close (srcfd);
  return result;
}

/* basename: from path 'src', return the basename
 * as a pointer into the same memory as 'src'
 */
static const char *
basename (const char *src)
{
  const char *bn = strrchr (src, '/');
  if (bn == NULL)
    bn = src;
  else
    ++bn;                       /* go past the '/' we found */
  return bn;
}

/* determine_target: allocates and creates a target filename from
 * the 'src' filename, an output directory 'odir', and a flag telling
 * whether we are 'encrypting' or not.
 */
static char *
determine_target (int encrypting, const char *odir, const char *src)
{
  static const char *extension = ".spritz";
  static const char *unenc = ".unenc";
  char *tgt = NULL;             /* the target filename */
  size_t tgtlen = 0;            /* the needed length of tgt */
  size_t odirlen = 0;
  size_t srclen = 0;

  /* First, determine the max space needed */
  if (odir != NULL)
    {
      odirlen = strlen (odir);
      src = basename (src);
    }

  /* just get 7 extra characters, in case we 
   * need to add a suffix, plus another for
   * the '\0'
   */
  srclen = strlen (src);
  tgtlen = odirlen + srclen + 7 + 1;

  /* Second, allocate and copy the filename */
  if ((tgt = malloc (tgtlen * sizeof (char))) == NULL)
    {
      fprintf (stderr, "%s: failed to allocate memory!\n", src);
      return NULL;
    }

  char *loc = tgt;
  if (odir != NULL)
    {
      strcpy (loc, odir);
      loc += odirlen;
    }
  strcpy (loc, src);
  loc += srclen;

  /* Third, determine the suffix */
  if (encrypting)
    {
      /* encrypting: add spritz */
      strcpy (loc, extension);
    }
  else
    {
      /* decrypting: remove a ".spritz" ending, if it's there */
      if ((loc - tgt > 7) && (!strcmp (loc - 7, extension)))
        {
          *(loc - 7) = '\0';
        }
      else
        {
          strcpy (loc, unenc);
        }
    }

  return tgt;
}

/* tty_echo turns on or off terminal echo */
static void
tty_echo (int echo, FILE * tty_file)
{
  struct termios tty;
  int tty_fd = fileno (tty_file);
  tcgetattr (tty_fd, &tty);
  if (echo)
    tty.c_lflag |= ECHO;
  else
    tty.c_lflag &= ~ECHO;

  (void) tcsetattr (tty_fd, TCSANOW, &tty);
}

/* read_pw_tty opens /dev/tty and speaks
 * directly to the user, asking for a password.
 * This way, it will work even when the program
 * is processing stdin.
 * 
 * It takes in the buffer for the hashed passwrord, and
 * the length of the requested hash.
 */
static bool
read_pw_tty (const char *prompt, uint8_t *const hashed_pw, size_t hash_len)
{
  char pwbuff[256];
  uint8_t *pw_hash = NULL;
  size_t len = 0;
  FILE *tty;

  memset (pwbuff, 0, sizeof (pwbuff));

  if ((tty = fopen ("/dev/tty", "r+")) == NULL)
    {
      fputs ("Couldn't open tty!\n", stderr);
      return false;
    }

  fputs (prompt, tty);
  fflush (tty);
  tty_echo (0, tty);

  if (fgets (pwbuff, sizeof (pwbuff), tty) == NULL)
    {
      fputs ("Error reading pw!\n", stderr);
    }

  tty_echo (1, tty);
  fputs ("\n", tty);
  fclose (tty);

  len = strlen (pwbuff);
  if (len <= 1)
    {
      fputs ("Error collecting password!\n", stderr);
      return false;
    }

  if (pwbuff[len - 1] == '\n')
    --len;

  spritz_mem_hash ((uint8_t *) pwbuff, len, hashed_pw, hash_len);
  return true;
}

/* collect_password will read the password
 * from the tty the specified number of times
 * and make sure they always match.
 *
 * Times will only be 1 or 2
 */
static bool
collect_password (int times, uint8_t *pw_hash, size_t hash_size)
{
  if(times == 1)
    return read_pw_tty ("Password: ", pw_hash, hash_size);
  
  /* need to collect the password twice, and compare them */
  bool result = false;
  uint8_t *second_hash = malloc(hash_size * sizeof(uint8_t));
  if (second_hash == NULL)
    {
      fputs("Could not allocate hash!\n", stderr);
      goto done;
    }
  
  if (! (read_pw_tty ("Password: ", pw_hash, hash_size) &&
	 (read_pw_tty ("Re-type password: ", second_hash, hash_size))) )
    goto done;

  if (memcmp (pw_hash, second_hash, hash_size) != 0)
    {
      fputs ("Passwords don't match!\n", stderr);
      goto done;
    }

  result = true;
 done:
  free (second_hash);
  return result;
}

int
crypt_main (int argc, char **argv)
{
  /* parse cmdline args */
  int c;
  size_t len;                   /* for counting strings during argument parsing */
  processor proc = encrypt_file;        /* assume we are encrypting */
  char *odir = NULL;            /* the output directory */
  uint8_t pw_hash[PW_HASH_LEN]; /* the hashed password */
  bool have_pw = false;         /* have we collected a password? */
  
  while ((c = getopt (argc, argv, "do:p:")) != -1)
    {
      switch (c)
        {
        case 'd':
          proc = decrypt_file;
          break;
        case 'o':
          if (odir != NULL)
            {
              fputs ("Multiple -o arguments not allowed!\n", stderr);
              return 1;
            }
          len = strlen (optarg);
          if (len >= 256)
            {
              fputs ("-o argument too long!\n", stderr);
              return 1;
            }
          odir = malloc ((len + 2) * sizeof (char));    /* +2 for '/', '\0' */
          if (odir == NULL)
            {
              fputs ("No memory!\n", stderr);
              return 1;
            }
          strcpy (odir, optarg);
          if (odir[len - 1] != '/')
            {
              /* add a final slash if needed */
              odir[len] = '/';
              odir[len + 1] = '\0';
            }
          break;
        case 'p':
          if (have_pw)
            {
              fputs ("Multiple -p arguments not allowed!\n", stderr);
              return 1;
            }
          len = strlen (optarg);
          spritz_mem_hash ((const uint8_t *) optarg, len, pw_hash, PW_HASH_LEN);
	  have_pw = true;
          break;
        }
    }

  /* if we didn't get a password on the command line, ask for it
   * on the terminal
   */
  if (! (have_pw ||
	 collect_password ((proc == decrypt_file) ? 1 : 2, pw_hash, PW_HASH_LEN)))
    return 1;
    
  srand (time (NULL));

  /* process the files, or stdin */
  int err = 0;
  if ((optind >= argc) ||
      ((argc - optind == 1) && (!strcmp (argv[optind], "-"))))
    {
      err += proc (pw_hash, "-", "-");
    }
  else
    {
      for (int idx = optind; idx < argc; ++idx)
        {
          const char *tgt =
            determine_target (proc == encrypt_file, odir, argv[idx]);
          if (tgt == NULL)
            {
              err += -1;
              continue;
            }
          err += proc (pw_hash, argv[idx], tgt);
          free ((void *) tgt);
        }
    }

  /* cleanup, although not necessary since we're exiting */
  free (odir);
  return (err < 0);
}
