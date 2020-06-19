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

/* generate bytes of random data */
static void
gen_rdata (uint8_t * buf, size_t len)
{
  for (size_t i = 0; i < len; ++i)
    {
      buf[i] = rand () & 0xff;;
    }
}

/* xor other into tgt, overwriting tgt */
static void
xor_arrays (uint8_t * tgt, const uint8_t * other, size_t len)
{
  while (len--)
    *tgt++ ^= *other++;
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

static bool
write_fully (int fd, const uint8_t * buf, size_t len)
{
  ssize_t sz;
  while ((sz = write (fd, buf, len)) != len)
    {
      if (sz < 0)
        return false;
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
        return false;
      len -= sz;
      buffer += sz;
    }
  return true;
}

static bool
fd_xor_copy (spritz_state s, int tgt_fd, int src_fd)
{
  ssize_t total = 0;

  uint8_t *const buffer = malloc (4096 * sizeof (uint8_t));

  ssize_t rsz;
  while ((rsz = read (src_fd, buffer, 4096)) > 0)
    {
      spritz_xor_many (s, buffer, rsz);
      if (!write_fully (tgt_fd, buffer, rsz))
        break;
    }

  free (buffer);
  return (rsz == 0);
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
determine_target (bool encrypting, const char *odir, const char *src)
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

  if (tgtlen >= 256)
    {
      fputs ("target filename can't be larger than 256 chars!\n", stderr);
      return NULL;
    }
  
  /* Second, allocate and copy the filename */
  if ((tgt = malloc (tgtlen * sizeof (char))) == NULL)
    {
      fputs ("failed to allocate memory!\n", stderr);
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
      strcpy (loc, extension);
    }
  else
    {
      /* decrypting: remove the extension ending, if it's there */
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
__attribute__((__malloc__))
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
typedef bool (*processor) (const uint8_t * const pw_hash, const char *src,
                           const char *tgt);

/* pull the embedded filename out of the encrypted file, returning
 * memory that must be freed with free().  Any name found inside is
 * appended to the directoryname of tgt.  If there is no embedded
 * filename, then a copy of tgt is returned.
 *
 * If the file is being piped, then ignore the embedded name.
 */
static char *
read_embedded_fname(spritz_state ss, int srcfd, const char *tgt)
{
  uint8_t one_byte = 0;
  if(read(srcfd, &one_byte, 1) != 1) {
    return NULL;
  }
  size_t embedded_size = (size_t)(one_byte ^ spritz_drip(ss));
  
  /* just allocate the max buffer we are allowing */
  char *ans = malloc(256);
  size_t dirsz = (size_t)(basename(tgt) - tgt);

  if((embedded_size + dirsz) >= 256)
    {
      fputs("output filename would be too long!", stderr);
      free(ans);
      return NULL;
    }

  if (embedded_size > 0)
    {
      memcpy(ans, tgt, dirsz); /* copy the directory in place */
      if(!read_fully(srcfd, ans+dirsz, embedded_size))
	{
	  fputs("could not read from source!", stderr);
	  free(ans);
	  return NULL;
	}
      spritz_xor_many(ss, ans+dirsz, embedded_size);
      ans[dirsz+embedded_size] = '\0';  /* null terminate it */
    }
  else
    strcpy(ans, tgt); 

  /* so, if the output was destined for stdout, keep that.  We still
   * had to do the work above regardless, to move forward the spritz
   * state.
   */
  if(tgt[0] == '-' && tgt[1] == '\0')
    {
      ans[0] = '-'; ans[1] = '\0';
    }
  
  return ans;
}

/* decrypt_file: decrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static bool
decrypt_file (const uint8_t * const pw_hash, const char *src, const char *tgt)
{
  bool result = false;
  uint8_t header[HDR_LEN];      /* IV, random data, hash of random data */
  int srcfd = -1, tgtfd = -1;
  char *embedded_filename = NULL;
  
  if ((srcfd = maybe_open (src, O_RDONLY, 0)) < 0)
    {
      fprintf (stderr, "%s error: Failed to open input file!\n",
               src);
      goto cleanup;
    }
    
  /* read in the header */
  if (!read_fully (srcfd, header, HDR_LEN))
    {
      fprintf (stderr, "%s Can't read header!\n", src);
      goto cleanup;
    }

  if (!decrypt_header (header, pw_hash))
    {
      fprintf (stderr, "%s Bad password or corrupted file.\n", src);
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

  /* ok, looks like the password was right... now get any embedded filenames */
  if ((embedded_filename = read_embedded_fname(ss, srcfd, tgt)) == NULL)
    {
      fprintf (stderr, "%s Could not read metadata (corrupted file?)\n", src);
      goto cleanup;
    }
  
  if ((tgtfd = maybe_open (embedded_filename, O_WRONLY | O_CREAT | O_EXCL, 0666)) < 0)
    {
      fprintf (stderr, "%s error: Failed to open  output file!\n",
               embedded_filename);
      goto cleanup;
    }

  /* read in the header */
  if (fd_xor_copy (ss, tgtfd, srcfd) < 0)
    {
      fprintf (stderr, "%s: Decryption error!\n", src);
      goto cleanup2;
    }

  result = true;                /* success! */
  if (tgtfd != 1)
    printf ("%s -decrypt-> %s\n", src, embedded_filename);

cleanup2:
  if (ss != NULL)
    destroy_spritz (ss);
cleanup:
  if (embedded_filename != NULL)
    free(embedded_filename);
  if (tgtfd >= 0)
    close (tgtfd);
  if (srcfd >= 0)
    close (srcfd);
  return result;
}

/* decrypt_file: decrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static bool
check_file (const uint8_t * const pw_hash, const char *src, const char *tgt)
{
  bool result = false;
  uint8_t header[HDR_LEN];      /* IV, random data, hash of random data */
  int srcfd = -1;
  char *embedded_filename = NULL;
  
  if ((srcfd = maybe_open (src, O_RDONLY, 0)) < 0)
    {
      fprintf (stderr, "%s error: Failed to open input file!\n",
               src);
      goto cleanup;
    }
    
  /* read in the header */
  if (!read_fully (srcfd, header, HDR_LEN))
    {
      fprintf (stderr, "%s Can't read header!\n", src);
      goto cleanup;
    }

  if (!decrypt_header (header, pw_hash))
    {
      fprintf (stderr, "%s Bad password or corrupted file.\n", src);
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

  /* ok, looks like the password was right... now get any embedded filenames */
  if ((embedded_filename = read_embedded_fname(ss, srcfd, tgt)) == NULL)
    {
      fprintf (stderr, "%s Could not read metadata (corrupted file?)\n", src);
      goto cleanup;
    }
  
  result = true;                /* success! */
  printf ("%s -success-> %s\n", src, embedded_filename);

cleanup2:
  if (ss != NULL)
    destroy_spritz (ss);
cleanup:
  if (embedded_filename != NULL)
    free(embedded_filename);
  if (srcfd >= 0)
    close (srcfd);
  return result;
}

/* decrypt_file: decrypt 'src' against password 'pw_hash', writing
 * the output to 'tgt'
 */
static bool
rekey (const char *src, const uint8_t * const pw_hash, const uint8_t * const npw_hash)
{
  bool result = false;
  uint8_t header[HDR_LEN];      /* IV, random data, hash of random data */
  int srcfd = -1;
  
  if ((srcfd = open(src, O_RDWR)) < 0)
    {
      fprintf (stderr, "%s error: Failed to open input file!\n",
               src);
      goto cleanup;
    }
    
  /* read in the header */
  if (!read_fully (srcfd, header, HDR_LEN))
    {
      fprintf (stderr, "%s Can't read header!\n", src);
      goto cleanup;
    }

  if (!decrypt_header (header, pw_hash))
    {
      fprintf (stderr, "%s Bad password or corrupted file.\n", src);
      goto cleanup;
    }

  /* now select a new IV and re-encrypt the header with the new password */
  gen_rdata(header, 4);
  encrypt_header(header, npw_hash);

  lseek(srcfd, 0, SEEK_SET);
  if (!write_fully (srcfd, header, HDR_LEN))
    {
      fprintf (stderr,
	       "%s could not write new key. Really sorry about that, "
	       "since your file may be corrupted now.\n",
	       src);
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
 * the output to 'tgt'
 */
static bool
encrypt_file (const uint8_t * const pw_hash, const char *src, const char *tgt)
{
  bool result = false;
  uint8_t header[HDR_LEN];
  int srcfd = -1, tgtfd = -1;
  const char *const base_fn = basename(src);
  
  /* Fill out and encrypt the header */
  gen_rdata (header, 8);
  spritz_mem_hash (header + HDR_CHECK_INT, 4, header + HDR_HASHCHECK_INT, 4);
  gen_rdata (header + HDR_KEY, KEY_LEN);
  spritz_state ss = generate_skipped_stream (header + HDR_KEY,
                                             (int) (header
                                                    [HDR_CHECK_INT + 1]));
  encrypt_header (header, pw_hash);

  if ((srcfd = maybe_open (src, O_RDONLY, 0)) < 0 ||
      (tgtfd = maybe_open (tgt, O_WRONLY | O_CREAT | O_EXCL, 0666)) < 0)
    {
      fprintf (stderr, "%s error: Failed to open input or output file!\n",
               src);
      goto cleanup;
    }

  /* now write the file out, header, base name, then payload */
  if (!write_fully (tgtfd, header, HDR_LEN))
    {
      fprintf (stderr, "%s error: Failed to write!\n", tgt);
      goto cleanup;
    }

  size_t base_len = strlen(base_fn);
  if( (base_len > 255) || (base_len == 1 && base_fn[0] == '-') )
    {
      base_len = 0;
    }
  size_t base_buffer_len = base_len + 1;
  uint8_t * base_buffer = malloc(base_buffer_len);
  base_buffer[0] = (uint8_t)(base_len & 0xff);
  memcpy(base_buffer+1, base_fn, base_len);
  spritz_xor_many(ss, base_buffer, base_buffer_len);  
  if (!write_fully(tgtfd, base_buffer, base_buffer_len))
    {
      fprintf (stderr, "%s error: Failed to write!\n", tgt);
      goto cleanup2;
    }
  
  if (!fd_xor_copy (ss, tgtfd, srcfd))
    {
      fprintf (stderr, "%s error: Failed to write!\n", tgt);
      goto cleanup2;
    }

  /* no errors! */
  result = true;
  if (tgtfd != 1)
    printf ("%s -encrypt-> %s\n", src, tgt);
  
 cleanup2:
  free(base_buffer);
 cleanup:
  if (ss != NULL)
    destroy_spritz (ss);
  if (tgtfd >= 0)
    close (tgtfd);
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

  while ((c = getopt (argc, argv, "dno:p:")) != -1)
    {
      switch (c)
        {
        case 'd':
          proc = &decrypt_file;
          break;
	case 'n':
	  proc = &check_file;
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
          spritz_mem_hash ((const uint8_t *) optarg, len, pw_hash, KEY_LEN);
          have_pw = true;
          break;
        }
    }

  /* if we didn't get a password on the command line, ask for it
   * on the terminal
   */
  if (!(have_pw ||
        collect_password ((proc == &encrypt_file) ? 2 : 1, pw_hash, KEY_LEN)))
    return 1;

  srand (time (NULL));

  /* process the files, or stdin */
  int err = 0;
  if ((optind >= argc) ||
      ((argc - optind == 1) && (!strcmp (argv[optind], "-"))))
    {
      err += ((*proc) (pw_hash, "-", "-") ? 0 : 1);
    }
  else
    {
      for (int idx = optind; idx < argc; ++idx)
        {
          const char *tgt =
            determine_target (proc == &encrypt_file, odir, argv[idx]);
          if (tgt == NULL)
            {
              err += -1;
              continue;
            }
          err += ((*proc) (pw_hash, argv[idx], tgt) ? 0 : 1);
          free ((void *) tgt);
        }
    }

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
      fputs("Can't rekey stdin (you have to give files on the cmdline!\n", stderr);
      return 1;
    }

  /* if we didn't get a password on the command line, ask for it
   * on the terminal
   */
  if(!have_pw)
    {
      fputs("Provide the old password.\n", stderr);
      if (!collect_password (1, pw_hash, KEY_LEN))
	return 1;
    }
  if(!have_npw)
    {
      fputs("Provide the new password.\n", stderr);
      if (!collect_password (2, npw_hash, KEY_LEN))
	return 1;
    }

  srand (time (NULL));

  /* process the files */
  int err = 0;
  for (int idx = optind; idx < argc; ++idx)
      err += (rekey(argv[idx], pw_hash, npw_hash) ? 0 : 1);

  return (err > 0);
}
