#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<time.h>

/* a global copy of the hashed pw */
uint8_t *pw_hash = NULL; 

/* generate bytes of random data */
static void gen_rdata(uint8_t *buf, size_t len) {
   for(size_t i = 0; i < len; ++i) {
     buf[i] = rand() & 0xff;;
   }
}

static int decrypt_file(const char*src, const char*tgt) {
   int result = -1;
   uint8_t buf[12];  // IV, random data, hash of random data

   int srcfd = open(src,O_RDONLY);
   if(srcfd < 0) goto exit;

   int tgtfd = open(tgt,O_WRONLY|O_CREAT|O_TRUNC, 0666);
   if(tgtfd < 0) { close(srcfd); goto exit; }

   /* read the IV, rdata, and hashed rdata */
   if(read(srcfd,buf,12) != 12) goto err_exit;   

   spritz_state ss = spritz_crypt(pw_hash, 32, buf, 4);

   /* now decrypt the random data and its hash... */
   spritz_xor_many(ss,buf+4, 8);
   uint8_t *rhash = spritz_mem_hash(buf+4,4,4);
   if(rhash == NULL) goto err_exit2;
   if(memcmp(rhash,buf+8,4) != 0) {
       result = -2;  
       goto err_exit2;
   }

   /* ok, looks like the password was right... now decrypt */
   if(spritz_xor_copy(ss,tgtfd,srcfd) < 0) goto err_exit2;

   result  = 0; /* no errors! */
   
err_exit2:
   if(ss != NULL) destroy_spritz(ss); 
err_exit:
   if(rhash != NULL) destroy_spritz_hash(rhash);
   close(tgtfd); 
   close(srcfd);
exit:
   return result;
}


static int encrypt_file(const char*src, const char*tgt) {
   int result = -1;
   uint8_t buf[12];  // IV, random data, hash of random data
   gen_rdata(buf, 8); 
   uint8_t *rhash = spritz_mem_hash(buf+4,4,4);
   if(rhash == NULL) goto exit;
   memcpy(buf+8,rhash,4);
   destroy_spritz_hash(rhash);

   int srcfd = open(src,O_RDONLY);
   if(srcfd < 0) goto exit;

   int tgtfd = open(tgt,O_WRONLY|O_CREAT|O_TRUNC, 0666);
   if(tgtfd < 0) { close(srcfd); goto exit; }

   /* write the IV unencrypted */
   if(write(tgtfd,buf,4) != 4) goto err_exit;   

   spritz_state ss = spritz_crypt(pw_hash, 32, buf, 4);

   /* now encrypt the random data and its hash... */
   spritz_xor_many(ss,buf+4, 8);
   if(write(tgtfd,buf+4,8) != 8) goto err_exit2;

   /* now copy the input to the output, xoring it... */
   if(spritz_xor_copy(ss,tgtfd,srcfd) < 0) goto err_exit2;

   result  = 0; /* no errors! */
   
err_exit2:
   if(ss != NULL) destroy_spritz(ss); 
err_exit:
   close(tgtfd); 
   close(srcfd);
exit:
   return result;
}

static void usage() {
  fprintf(stderr,"Usage: spritz-crypt -p pw\n");
  fprintf(stderr,"  -h      Display this help message.\n");
  fprintf(stderr,"  -p pwd  Set the password to use.\n");
  exit(2);
}

static void panic(const char*msg) {
  fputs(msg,stderr);
  exit(1);
}

/* parse a file name, allowing for escapes... stop on whitespace or '\0' */
static int parse_fname(const char *line, char *fname) {
   int escaped = 0;
   const char *const orig_fname = fname;

   while( (*line != '\0') &&
          (escaped || *line != ' ') &&
          (escaped || *line != '\n') ) {
       if(escaped) {
          *fname++ = *line++;
	  escaped = 0;
       } else {
          if(*line == '\\') {
             escaped = 1;
	  } else {
             *fname++ = *line;
	  }
	  ++line;
       }
   }

   *fname = '\0';
   return (fname - orig_fname);
}

/* takes the input line, and fills out `cmd`, `src_name`, and `tgt_name` with
 * what it can pull from the input.
 */
static int parse_input(const char *line, char *cmd, char *src_name, char *tgt_name)  {
     *cmd = *line++;
     /* cmd must be D or E, and followed by a space */
     if( (*cmd != 'D' && *cmd != 'E') ||
         (*line++ != ' ') ) return -1;

     while(*line == ' ') ++line; /* skip spaces */

     int flen;
     if((flen = parse_fname(line,src_name)) <= 0) return -1;
     
     /* the filename must be followed by a space */
     line += flen;
     if(*line++ != ' ') return -1;    
     while(*line == ' ') ++line; /* skip spaces */

     if((flen = parse_fname(line,tgt_name)) <= 0) return -1;

     return 0; /* success */
}

/* The protocol: 
 *    send "OK %s" --> print to stdout, and I'm ready for more input
 *    send "ER %s" --> print to stderr, and I'm ready for more input
 */
static void run_job(void) {
     char *src_name = malloc(300*sizeof(char));
     char *tgt_name = malloc(300*sizeof(char));
     char *buffer   = malloc(650*sizeof(char));

     if( (src_name == NULL) || (tgt_name == NULL) || (buffer == NULL) )
	     panic("Couldn't allocate!\n");

     if(puts("OK") < 0) panic("Can't write!\n");

     ssize_t len;
     while( !feof(stdin) ) {
        char *const line = fgets(buffer, 650, stdin);
	if(line == NULL) return;

	char cmd;  /* 'D'ecrypt or 'E'ncrypt */
        if(parse_input(line, &cmd, src_name, tgt_name) < 0) {
		printf("ER Bad Input line! <%s>\n",buffer);
		continue;
	}

        int err = 0;
	switch(cmd) {
	case 'D':
           if((err = decrypt_file(src_name, tgt_name)) != 0) {
               if(err == -2) printf("ER %s bad password or corrupted file.\n",src_name);    
               else printf("ER %s decryption error.\n",src_name);    
           } else {
               printf("OK %s -decrypt-> %s\n",src_name,tgt_name);
           }
           break;
	case 'E':
           if(encrypt_file(src_name, tgt_name) != 0) {
               printf("ER %s encryption error.\n",src_name);    
           } else {
               printf("OK %s -encrypt-> %s\n",src_name,tgt_name);
           }
        }

     }
}


int main(int argc, char **argv) {
  /* parse cmdline args */
  int c;
  size_t pwlen;

  if( (setvbuf(stdin, NULL, _IOLBF, 4096) != 0)  ||
      (setvbuf(stdout, NULL, _IOLBF, 4096) != 0) ) {
	fputs("Error setting buffering!\n",stderr);
	return 1;
  }

  while ( (c = getopt(argc,argv,"hp:")) != -1 ) {
     switch(c) {
     case 'h':
	usage();
	break;
     case 'p':
        pwlen = strlen(optarg); 
        pw_hash = spritz_mem_hash((const uint8_t *)optarg, pwlen, 32);
        break;
     } 
  }

  if(pw_hash == NULL) { usage(); }

  if(optind != argc) { usage(); }
  srand(time(NULL));
  run_job();

  return 0;
}

