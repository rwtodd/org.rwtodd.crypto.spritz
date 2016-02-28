#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<time.h>


/* generate bytes of random data */
static void gen_rdata(uint8_t *buf, size_t len) {
   for(size_t i = 0; i < len; ++i) {
     buf[i] = rand() & 0xff;;
   }
}

static int maybe_open(const char *const fname, int flags, mode_t mode) {
	int reading = (flags == O_RDONLY);
	if(!strcmp(fname,"-")) {
	    return reading?0:1;  /* stdin:stdout */
	}

	return reading?open(fname,flags):open(fname,flags,mode);
}

typedef int (*processor)(const uint8_t*const, const char*, const char*);

static int decrypt_file(const uint8_t *const pw_hash, const char*src, const char*tgt) {
   int result = 1;
   uint8_t buf[12];  // IV, random data, hash of random data

   int srcfd = maybe_open(src,O_RDONLY,0);
   if(srcfd < 0) goto exit;

   int tgtfd = maybe_open(tgt,O_WRONLY|O_CREAT|O_TRUNC, 0666);
   if(tgtfd < 0) { close(srcfd); goto exit; }

   /* read the IV, rdata, and hashed rdata */
   if(read(srcfd,buf,12) != 12) goto err_exit;   

   spritz_state ss = spritz_crypt(pw_hash, 32, buf, 4);

   /* now decrypt the random data and its hash... */
   spritz_xor_many(ss,buf+4, 8);
   uint8_t *rhash = spritz_mem_hash(buf+4,4,4);
   if(rhash == NULL) goto err_exit2;
   if(memcmp(rhash,buf+8,4) != 0) {
       result = 2;  
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
   switch(result) {
   case 0: 
	  if(tgtfd != 1) printf("%s -decrypt-> %s\n",src,tgt);
	  break;
   case 2:
	  fprintf(stderr, "%s: bad password or corrupt file!\n", src);
	  break;
   default:
	  fprintf(stderr, "%s: error decrypting.\n", src);
   }
   return (result != 0);
}


static int encrypt_file(const uint8_t *const pw_hash, const char*src, const char*tgt) {
   int result = 1;
   uint8_t buf[12];  // IV, random data, hash of random data
   gen_rdata(buf, 8); 
   uint8_t *rhash = spritz_mem_hash(buf+4,4,4);
   if(rhash == NULL) goto exit;
   memcpy(buf+8,rhash,4);
   destroy_spritz_hash(rhash);

   int srcfd = maybe_open(src,O_RDONLY,0);
   if(srcfd < 0) goto exit;

   int tgtfd = maybe_open(tgt,O_WRONLY|O_CREAT|O_TRUNC, 0666);
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
   if(result == 0) {
	  if(tgtfd != 1) printf("%s -encrypt-> %s\n",src,tgt);
   } else {
	  fprintf(stderr, "%s: error encrypting.\n", src);
   }
   return result;
}

static void usage() {
  fprintf(stderr,"Usage: spritz-crypt [options] [file1 file2...]\n");
  fprintf(stderr,"  -d      Decrypt the input files.\n");
  fprintf(stderr,"  -h      Display this help message.\n");
  fprintf(stderr,"  -o dir  Put the output files in dir.\n");
  fprintf(stderr,"  -p pwd  Set the password to use.\n");
  exit(2);
}

static const char * basename(const char*src) {
	const char* answer = strrchr(src,'/');
	if(answer == NULL) answer = src;	
	else ++answer; /* go past the '/' we found */
	return answer;
}

static char *determine_target(int encrypting, const char* odir, const char*src) {
     static const char *extension = ".spritz";
     static const char *unenc = ".unenc";
     char *answer = NULL;
     size_t anslen = 0;
     size_t odirlen = 0;
     size_t srclen = 0;

     /* First, determine the max space needed */
     if(odir == NULL) {
	/* just get 7 extra characters, in case we need to add a suffix */
	srclen = strlen(src);
   	anslen = srclen + 7;	
     } else {
	/* we have to find the basename */
	src = basename(src);
	srclen = strlen(src);
	odirlen = strlen(odir);

        /* +7 is for a suffix */
 	anslen = odirlen + srclen + 7;
     } 

     /* Second, allocate and copy the filename */
     answer = malloc(anslen * sizeof(char));
     if(answer == NULL) return NULL;
    
     char *tgt = answer;
     if(odir != NULL) {
	strcpy(tgt,odir); tgt += odirlen;
     } 
     strcpy(tgt,src);
     tgt += srclen;

     /* Third, determine the suffix */
     if(encrypting) {
	/* encrypting: add spritz */
	strcpy(tgt,extension);
     } else {
        /* decrypting: remove a ".spritz" ending, if it's there */    
	if( (tgt - answer > 7) && (!strcmp(tgt-7,extension)) ) {
		*(tgt-7) = '\0';
	} else {
		strcpy(tgt,unenc);
	}
     }

     return answer;
}

int main(int argc, char **argv) {
  /* parse cmdline args */
  int c;
  size_t len; /* for counting strings during argument parsing */
  processor proc = encrypt_file; /* assume we are encrypting */
  char * odir = NULL;  /* the output directory */
  uint8_t *pw_hash = NULL;   /* the hashed password */

  while ( (c = getopt(argc,argv,"dho:p:")) != -1 ) {
     switch(c) {
     case 'd':
	proc = decrypt_file;
	break;
     case 'h':
	usage();
	break;
     case 'o':
	if(odir != NULL) { fputs("Multiple -o arguments not allowed!\n",stderr); exit(1); }
	len = strlen(optarg) + 1;
	if(len >= 256) { fputs("-o argument too long!\n",stderr); exit(1); }
	odir = malloc(len*sizeof(char));
	if(odir == NULL) { fputs("No memory!\n",stderr); exit(1); }
	strcpy(odir,optarg);
	if(odir[len-2] != '/') { 
		/* add a final slash if needed */
		odir[len-1] = '/'; 
		odir[len] = '\0'; 
	}
 	break;	
     case 'p':
	if(pw_hash != NULL) { fputs("Multiple -p arguments not allowed!\n",stderr); exit(1); }
        len = strlen(optarg); 
        pw_hash = spritz_mem_hash((const uint8_t *)optarg, len, 32);
        break;
     } 
  }

  if(pw_hash == NULL) { usage(); }
  srand(time(NULL));

  int errcnt = 0;
  if( (optind >= argc) || 
      ((argc - optind == 1) && (!strcmp(argv[optind],"-"))) 
    ) {
	errcnt += proc(pw_hash, "-", "-");
  } else {
	for(int idx = optind; idx < argc; ++idx) {
		const char *tgt = determine_target(proc==encrypt_file, odir, argv[idx]);
		errcnt += proc(pw_hash, argv[idx], tgt);
		free((void*)tgt);
	}
  }

  /* cleanup, although not necessary since we're exiting */
  destroy_spritz_hash(pw_hash);
  free(odir);
  return (errcnt == 0)?0:1;
}

