#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<time.h>
#include<termios.h>


/* define the file header offsets */
#define HDR_IV 0
#define HDR_CHECK_INT 4
#define HDR_HASHCHECK_INT 8
#define HDR_KEY 12
#define KEY_LEN 64
#define HDR_LEN (HDR_KEY+KEY_LEN)

/*
 * ************************************************************
 * Utilities Section
 * ************************************************************
 */

/* our source for keys */
static struct s_spritz_state *random_source;

static bool
seed_rand (void)
{
  /* 
   * it's possible/likely that dev/urandom doesn't have
   * KEY_LEN bytes of randomness, but we won't do better
   * elsewhere, and maybe one day it might, so...
   */
  uint8_t noise[KEY_LEN];
  int urand = open ("/dev/urandom", O_RDONLY);
  if (urand < 0)
    {
      perror ("open urandom");
      return false;
    }
  if (read (urand, noise, KEY_LEN) != KEY_LEN)
    {
      fputs ("failed to read urandom!", stderr);
      return false;
    }
  close (urand);

  if ((random_source = create_spritz ()) == NULL)
    {
      fputs ("could not create random source!", stderr);
      return false;
    }
  spritz_absorb_many (random_source, noise, KEY_LEN);
  spritz_absorb_stop (random_source);
  /* add the low byte of the UNIX time stamp for laughs */
  spritz_absorb (random_source, (uint8_t) (time (NULL) & 0xff));
  return true;
}

/* generate bytes of random data */
static void
gen_rdata (uint8_t * buf, size_t len)
{
  spritz_drip_many (random_source, buf, len);
}

/* xor other into tgt, overwriting tgt */
static void
xor_arrays (uint8_t * tgt, const uint8_t * other, size_t len)
{
  while (len--)
    *tgt++ ^= *other++;
}

/* maybe_open: A wrapper for open().  If the filename isnt "-", open 
 * filename. Otherwise, return STDIN_FILENO
 */
static int
maybe_open (const char *const fname)
{
  if (!strcmp (fname, "-"))
    return STDIN_FILENO;

  int result = open (fname, O_RDONLY);
  if (result < 0)
    perror ("Cannot open input");
  return result;
}

static bool
write_fully (int fd, const uint8_t * buf, size_t len)
{
  ssize_t sz;
  while ((sz = write (fd, buf, len)) != len)
    {
      if (sz < 0)
        {
          perror ("`write_fully` failed to write");
          return false;
        }
      len -= sz;
      buf += sz;
    }

  return true;
}

static bool
read_fully (int fd, uint8_t * buffer, size_t len)
{
  ssize_t sz;
  while ((sz = read (fd, buffer, len)) != len)
    {
      if (sz < 0)
        {
          perror ("`read_fully` failed to read");
          return false;
        }
      len -= sz;
      buffer += sz;
    }
  return true;
}

static bool
fd_xor_copy (spritz_state s, int tgt_fd, int src_fd)
{
  ssize_t total = 0;

  uint8_t *const buffer = malloc (BUFSIZ * sizeof (uint8_t));

  ssize_t rsz;
  while ((rsz = read (src_fd, buffer, BUFSIZ)) > 0)
    {
      spritz_xor_many (s, buffer, rsz);
      if (!write_fully (tgt_fd, buffer, rsz))
        break;
    }

  if (rsz < 0)
    perror ("`xor_copy` failed to read");
  free (buffer);
  return (rsz == 0);
}

/*
 * ************************************************************
 * Headers Section
 * ************************************************************
 */

/*
 * Keygen is just rounds and rounds of hashing.
 */
static void
keygen (uint8_t * tgt, const uint8_t * hashed_pw, const uint8_t * iv,
        int times)
{
  uint8_t iv_copy[4];
  memcpy (tgt, hashed_pw, KEY_LEN);
  memcpy (iv_copy, iv, 4);

  spritz_state s = create_spritz ();
  while (times--)
    {
      size_t bias = iv_copy[0] & 3;
      spritz_absorb_many (s, iv_copy, 4);
      spritz_absorb_stop (s);
      spritz_absorb_many (s, iv + bias, 4 - bias);
      spritz_absorb_stop (s);
      spritz_absorb_many (s, tgt, KEY_LEN);
      spritz_absorb_stop (s);
      spritz_drip_many (s, tgt, KEY_LEN);
      spritz_drip_many (s, iv_copy, 4);
    }
  destroy_spritz (s);
}

/* create a spritz_state ready to go using the key and the iv,
 * skipping some output in case the first few bytes are easy
 * to attack.
 */

static spritz_state
generate_skipped_stream (const uint8_t * key, int skip_amt)
__attribute__((__malloc__));

static spritz_state
generate_skipped_stream (const uint8_t * key, int skip_amt)
{
  spritz_state stream = create_spritz ();
  if (stream == NULL)
    return NULL;

  spritz_absorb_many (stream, key, KEY_LEN);
  int to_skip = 2048 + skip_amt;
  while (to_skip--)
    spritz_drip (stream);
  return stream;
}

/*
 * take a filled-in header, and encrypt it via the provided
 * hashed password.  The header is expected to already have
 * an IV, a check-integer + hash, and a KEY.
 */
static void
encrypt_header (uint8_t * header, const uint8_t * pw_hash)
{
  uint8_t pw_key[KEY_LEN];
  uint8_t iv[4];

  memcpy (iv, header + HDR_IV, 4);
  /* IV is encrypted with the end of the single pw-hash */
  xor_arrays (header + HDR_IV, pw_hash + KEY_LEN - 4, 4);
  keygen (pw_key, pw_hash, iv, 20000 + ((int) (iv[3])));
  spritz_state s = generate_skipped_stream (pw_key, (int) (iv[1]));

  /* Now, encrypt the check integer and its hash against the generated key-stream,
   * and then skip more of the key-stream before encrypting the actual payload key.
   *
   * make the amount of stream to skip dependent on the check int value
   */
  int extra_skip = 5 + (int) (header[HDR_CHECK_INT]);

  spritz_xor_many (s, header + HDR_CHECK_INT, 8);
  while (extra_skip--)
    spritz_drip (s);
  spritz_xor_many (s, header + HDR_KEY, KEY_LEN);

  destroy_spritz (s);
}

/*
 * Take an encrypted header and decrypt it using a provided hashed password.
 */
static bool
decrypt_header (uint8_t * header, const uint8_t * pw_hash)
{
  uint8_t pw_key[KEY_LEN];
  bool result = false;

  /* IV is encrypted with the end of the single pw-hash */
  xor_arrays (header + HDR_IV, pw_hash + KEY_LEN - 4, 4);

  keygen (pw_key, pw_hash, header + HDR_IV,
          20000 + ((int) (header[HDR_IV + 3])));
  spritz_state s =
    generate_skipped_stream (pw_key, (int) (header[HDR_IV + 1]));

  /* Now, decrypt the check integer and its hash against the generated key-stream,
   * and then skip more of the key-stream before decrypting the actual payload key.
   *
   * make the amount of stream to skip dependent on the check int value
   */
  spritz_xor_many (s, header + HDR_CHECK_INT, 8);

  /* now check that the check int hashes to the value that follows it */
  uint8_t rhash[4];
  spritz_mem_hash (header + HDR_CHECK_INT, 4, rhash, 4);
  if (memcmp (rhash, header + HDR_HASHCHECK_INT, 4) != 0)
    goto done;

  int extra_skip = 5 + (int) (header[HDR_CHECK_INT]);
  while (extra_skip--)
    spritz_drip (s);
  spritz_xor_many (s, header + HDR_KEY, KEY_LEN);
  result = true;                /* success! */

done:
  destroy_spritz (s);
  return result;
}

/*
 * ************************************************************
 * Decrypting Section
 * ************************************************************
 */

/* processor, the type that can either be an encryptor or decryptor */
typedef bool (*processor) (const uint8_t * const pw_hash, const char *src);

/* decrypt_file: decrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static bool
decrypt_file (const uint8_t * const pw_hash, const char *src)
{
  bool result = false;
  uint8_t header[HDR_LEN];
  int srcfd = -1;

  if ((srcfd = maybe_open (src)) < 0)
    goto cleanup;

  /* read in the header */
  if (!read_fully (srcfd, header, HDR_LEN))
    goto cleanup;

  if (!decrypt_header (header, pw_hash))
    {
      fprintf (stderr, "%s Bad password or corrupted file?\n", src);
      goto cleanup;
    }

  spritz_state ss = generate_skipped_stream (header + HDR_KEY,
                                             (int) (header
                                                    [HDR_CHECK_INT + 1]));
  if (ss == NULL)
    {
      fputs ("could not generate spritz state!\n", stderr);
      goto cleanup;
    }

  if (fd_xor_copy (ss, STDOUT_FILENO, srcfd) < 0)
    goto cleanup2;

  result = true;                /* success! */

cleanup2:
  if (ss != NULL)
    destroy_spritz (ss);
cleanup:
  if (srcfd >= 0)
    close (srcfd);
  return result;
}

/* check_file: decrypt 'src' header to check that the password
 * appears to be correct.
 */
static bool
check_file (const uint8_t * const pw_hash, const char *src)
{
  bool result = false;
  uint8_t header[HDR_LEN];
  int srcfd = -1;

  if ((srcfd = maybe_open (src)) < 0)
    goto cleanup;

  /* read in the header */
  if (!read_fully (srcfd, header, HDR_LEN))
    goto cleanup;

  if (!decrypt_header (header, pw_hash))
    {
      fprintf (stderr, "%s Bad password or corrupted file.\n", src);
      goto cleanup;
    }

  result = true;                /* success! */
  printf ("%s correct password.\n", src);

 cleanup:
  if (srcfd >= 0)
    close (srcfd);
  return result;
}

/* rekey_file: decrypt the `src` header, and then re-encrypt it with a new
 * password.
 */
static bool
rekey (const char *src, const uint8_t * const pw_hash,
       const uint8_t * const npw_hash)
{
  bool result = false;
  uint8_t header[HDR_LEN];      /* IV, random data, hash of random data */
  int srcfd = -1;

  if ((srcfd = open (src, O_RDWR)) < 0)
    {
      perror (src);
      goto cleanup;
    }

  /* read in the header */
  if (!read_fully (srcfd, header, HDR_LEN))
    goto cleanup;

  if (!decrypt_header (header, pw_hash))
    {
      fprintf (stderr, "%s Bad password or corrupted file.\n", src);
      goto cleanup;
    }

  /* now select a new IV and re-encrypt the header with the new password */
  gen_rdata (header, 4);
  encrypt_header (header, npw_hash);

  lseek (srcfd, 0, SEEK_SET);
  if (!write_fully (srcfd, header, HDR_LEN))
    {
      fprintf (stderr,
               "%s could not write new key. Really sorry about that, "
               "since your file may be corrupted now.\n", src);
      goto cleanup;
    }

  result = true;                /* success! */
  printf ("%s rekeyed.\n", src);

cleanup:
  if (srcfd >= 0)
    close (srcfd);
  return result;
}

/*
 * ************************************************************
 * Encrypting Section
 * ************************************************************
 */

/* encrypt_file: encrypt 'src' against password 'pw_hash', writing
 * the output to stdout
 */
static bool
encrypt_file (const uint8_t * const pw_hash, const char *src)
{
  bool result = false;
  uint8_t header[HDR_LEN];
  int srcfd = -1;

  if (!seed_rand ())
    return false;

  /* Fill out and encrypt the header */
  gen_rdata (header, 8);
  spritz_mem_hash (header + HDR_CHECK_INT, 4, header + HDR_HASHCHECK_INT, 4);
  gen_rdata (header + HDR_KEY, KEY_LEN);
  spritz_state ss = generate_skipped_stream (header + HDR_KEY,
                                             (int) (header
                                                    [HDR_CHECK_INT + 1]));
  encrypt_header (header, pw_hash);

  if ((srcfd = maybe_open (src)) < 0)
    goto cleanup;

  /* now write the file out, header, base name, then payload */
  if (!write_fully (STDOUT_FILENO, header, HDR_LEN))
    goto cleanup;

  if (!fd_xor_copy (ss, STDOUT_FILENO, srcfd))
    goto cleanup;

  /* no errors! */
  result = true;

cleanup:
  if (ss != NULL)
    destroy_spritz (ss);
  if (srcfd >= 0)
    close (srcfd);
  return result;
}

/*
 * ************************************************************
 * TTY passwords Section
 * ************************************************************
 */

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
read_pw_tty (const char *prompt, uint8_t * const hashed_pw, size_t hash_len)
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
collect_password (int times, uint8_t * pw_hash, size_t hash_size)
{
  if (times == 1)
    return read_pw_tty ("Password: ", pw_hash, hash_size);

  /* need to collect the password twice, and compare them */
  bool result = false;
  uint8_t *second_hash = malloc (hash_size * sizeof (uint8_t));
  if (second_hash == NULL)
    {
      fputs ("Could not allocate hash!\n", stderr);
      goto done;
    }

  if (!(read_pw_tty ("Password: ", pw_hash, hash_size) &&
        (read_pw_tty ("Re-type password: ", second_hash, hash_size))))
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


/*
 * ************************************************************
 * The CRYPT main program Section
 * ************************************************************
 */

int
crypt_main (int argc, char **argv)
{
  /* parse cmdline args */
  int c;
  size_t len;                   /* for counting strings during argument parsing */
  processor proc = &encrypt_file;       /* assume we are encrypting */
  char *odir = NULL;            /* the output directory */
  uint8_t pw_hash[KEY_LEN];     /* the hashed password */
  bool have_pw = false;         /* have we collected a password? */

  while ((c = getopt (argc, argv, "dnp:")) != -1)
    {
      switch (c)
        {
        case 'd':
          proc = &decrypt_file;
          break;
        case 'n':
          proc = &check_file;
          break;
        case 'p':
          if (have_pw)
            {
              fputs ("Multiple -p arguments not allowed!\n", stderr);
              return 1;
            }
          len = strlen (optarg);
          spritz_mem_hash ((const uint8_t *) optarg, len, pw_hash, KEY_LEN);
          have_pw = true;
          break;
        }
    }

  /* if we have more than one argument left over, and it's not the check
   * function, complain.  Encryption and decryption only work on one file
   * at a time.
   */
  if (argc - optind > 1 && proc != &check_file)
    {
      fputs ("extra command line arguments detected!\n", stderr);
      return 1;
    }

  /* if we didn't get a password on the command line, ask for it
   * on the terminal
   */
  if (!(have_pw ||
        collect_password ((proc == &encrypt_file) ? 2 : 1, pw_hash, KEY_LEN)))
    return 1;

  /* process the file, or stdin */
  int err = 0;
  if ((optind >= argc) ||
      ((argc - optind == 1) && !strcmp (argv[optind], "-")))
    err += ((*proc) (pw_hash, "-") ? 0 : 1);
  else
    for (int idx = optind; idx < argc; ++idx)
      err += ((*proc) (pw_hash, argv[idx]) ? 0 : 1);

  /* cleanup, although not necessary since we're exiting */
  free (odir);
  return (err > 0);
}

/*
 * ************************************************************
 * The REKEY main program Section
 * ************************************************************
 */

int
rekey_main (int argc, char **argv)
{
  /* parse cmdline args */
  int c;
  size_t len;                   /* for counting strings during argument parsing */
  uint8_t pw_hash[KEY_LEN];     /* the hashed password */
  bool have_pw = false;         /* have we collected a password? */
  uint8_t npw_hash[KEY_LEN];    /* the new password, hashed */
  bool have_npw = false;        /* have we collected the new password? */

  if (!seed_rand ())
    return 1;

  while ((c = getopt (argc, argv, "o:n:")) != -1)
    {
      switch (c)
        {
        case 'o':
          if (have_pw)
            {
              fputs ("Multiple -o arguments not allowed!\n", stderr);
              return 1;
            }
          len = strlen (optarg);
          spritz_mem_hash ((const uint8_t *) optarg, len, pw_hash, KEY_LEN);
          have_pw = true;
          break;

        case 'n':
          if (have_npw)
            {
              fputs ("Multiple -n arguments not allowed!\n", stderr);
              return 1;
            }
          len = strlen (optarg);
          spritz_mem_hash ((const uint8_t *) optarg, len, npw_hash, KEY_LEN);
          have_npw = true;
          break;
        }
    }

  /* error out if there is nothing to process */
  if ((optind >= argc) ||
      ((argc - optind == 1) && (!strcmp (argv[optind], "-"))))
    {
      fputs ("Can't rekey stdin (you have to give files on the cmdline!\n",
             stderr);
      return 1;
    }

  /* if we didn't get a password on the command line, ask for it
   * on the terminal
   */
  if (!have_pw)
    {
      fputs ("Provide the old password.\n", stderr);
      if (!collect_password (1, pw_hash, KEY_LEN))
        return 1;
    }
  if (!have_npw)
    {
      fputs ("Provide the new password.\n", stderr);
      if (!collect_password (2, npw_hash, KEY_LEN))
        return 1;
    }

  /* process the files */
  int err = 0;
  for (int idx = optind; idx < argc; ++idx)
    err += (rekey (argv[idx], pw_hash, npw_hash) ? 0 : 1);

  return (err > 0);
}
