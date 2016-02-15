#include "spritz.h"
#include "lineio.h"
#include<stdint.h>
#include<stdio.h>
#include<signal.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<poll.h>
#include<errno.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<time.h>

/* a global constant for the extension */
const char *const extension = ".spritz";
const size_t extlen = 7;

/* a global copy of the hashed pw */
uint8_t *pw_hash = NULL; 

static void process_password(const char *pw) {
  size_t len = strlen(pw); 
  pw_hash = spritz_mem_hash(pw, len, 32);

}

/* generate bytes of random data */
static void gen_rdata(uint8_t *buf, size_t len) {
   for(size_t i = 0; i < len; ++i) {
     buf[i] = rand() & 0xff;;
   }
}

/* check if the end of a string matches a given string */
static int ending(const char *src, size_t flen, const char *end, size_t elen) {
  if(flen < elen) { return 0; }
  return (memcmp(src+flen-elen,end,elen) == 0)?1:0;
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

enum { P_READ, P_WRITE } ;

static void usage() {
  fprintf(stderr,"Usage: spritz-crypt [options] file1 file2...\n");
  fprintf(stderr,"  -h      Display this help message.\n");
  fprintf(stderr,"  -j n    Run n files at once.\n");
  fprintf(stderr,"  -p pwd  Set the password to use.\n");
  fprintf(stderr,"  -c      Run in interactive child mode\n");
  exit(2);
}

typedef struct job {
  int fd_to;
  int fd_from;
  pid_t pid;
} job;

static void panic(const char*msg) {
  fprintf(stderr,msg);
  exit(1);
}

/* The protocol: 
 *    send "OK %s" --> print to stdout, and I'm ready for more input
 *    send "ER %s" --> print to stderr, and I'm ready for more input
 */
static void run_job(int readfd, int writefd) {
     char src_name[300];
     char tgt_name[300];

     if(write_line(writefd,"OK") < 0) return;

     ssize_t flen;
     while ( (flen = read_line(readfd, src_name, sizeof(src_name))) > 0 )
     {
        /* chop off the newline */
        src_name[--flen] = '\0'; 

        if(ending(src_name,flen,extension,extlen)) {
            /* we need to decrypt */
            memcpy(tgt_name,src_name,flen - extlen);
           tgt_name[flen-extlen] = '\0'; 

           int err = 0;
           if((err = decrypt_file(src_name, tgt_name)) != 0) {
               if(err == -2) write_line(writefd,"ER %s bad password or corrupted file.",src_name);    
               else write_line(writefd,"ER %s decryption error.",src_name);    
           } else {
               write_line(writefd,"OK %s decrypted.",src_name);
           }

        } else {
            /* we need to encrypt */
            strcpy(tgt_name,src_name);
            strcpy(tgt_name+flen, extension); 

            if(encrypt_file(src_name, tgt_name) != 0) {
               write_line(writefd,"ER %s encryption error.",src_name);    
            } else {
               write_line(writefd,"OK %s encrypted.",src_name);
            }
        }

     }
}

static job* create_jobs(int num) {
  job *ans = malloc(num*sizeof(job));
  if(ans == NULL) panic("Out of memory!");

  unsigned int seed = time(NULL);

  for(int idx = 0 ; idx < num; ++idx) {
     ++seed;
     int pipe1[2]; /* parent -> child */
     int pipe2[2]; /* child -> parent */
     if( pipe(pipe1) != 0 ) panic("Can't create pipe!");
     if( pipe(pipe2) != 0 ) panic("Can't create pipe!");
     if((ans[idx].pid = fork()) < 0) panic("Can't fork!");

     if(ans[idx].pid == 0) {
        /* we are the child... close the unused channels */
        close(pipe1[P_WRITE]);
        close(pipe2[P_READ]);

        /* seed the random number generator */
        srand(seed);

        /* process requests */
        run_job(pipe1[P_READ], pipe2[P_WRITE]); 
        exit(0);
     } else {
        /* we are the parent... remember the communication channels */
        close(pipe1[P_READ]);
        close(pipe2[P_WRITE]);
        ans[idx].fd_to = pipe1[P_WRITE];
        ans[idx].fd_from = pipe2[P_READ];
     }
  }
  return ans;
}

static int handle_input(int fd){ 
  char inbuf[1024];
  int errs = 0;

  ssize_t rsz = read_line(fd, inbuf, 1024);
  if(rsz == 0) { return 0; }
  if(rsz < 3) {
     fprintf(stderr,"Processing Error!\n");
     return 1;
  }
  if(inbuf[0] == 'E') errs = 1;
  if(inbuf[2] == ' ') fputs(inbuf+3, (errs==0)?stdout:stderr);

  return errs;
}

static int serve_file(int fd, const char*fname) {
  if (write_line(fd, "%s", fname) < 0) return 1;
  return 0;
}

int main(int argc, char **argv) {
  /* setup signals */
  struct sigaction act;

  sigfillset(&act.sa_mask);
  act.sa_flags   = 0;
  act.sa_handler = SIG_DFL;
  sigaction(SIGCHLD, &act, 0);

  /* parse cmdline args */
  int c;
  int njobs = 1;
  int child_mode = 0;
  size_t pwlen;

  while ( (c = getopt(argc,argv,"hp:j:c")) != -1 ) {
     switch(c) {
     case 'c':
        child_mode = 1; 
        break;
     case 'h':
        usage();
        break;
     case 'j':
        njobs = atoi(optarg);
        if(njobs < 1) njobs = 1;
        break;
     case 'p':
        pwlen = strlen(optarg); 
        pw_hash = spritz_mem_hash(optarg, pwlen, 32);
        break;
     } 
  }

  if(pw_hash == NULL) { usage(); }

  if(child_mode == 1) {
      if(optind != argc) { usage(); }
      srand(time(NULL));
      run_job(0,1);
      exit(0);
  }

  if(argc <= optind) { usage(); }

  /* set up concurrency */
  job *jobs = create_jobs(njobs);
  int nerr = 0;

  /* set up for poll() */
  struct pollfd pfds[njobs];
  for(int idx = 0; idx < njobs; ++idx) {
     pfds[idx].fd = jobs[idx].fd_from;
     pfds[idx].events = POLLIN|POLLHUP;
  }

  /* serve jobs */
  int fname_idx = optind;
  while(njobs > 0) {
     /* poll for available child */
     int num_events = poll(pfds, njobs, -1);
     if(num_events == 0) {
         continue;
     } else if( (num_events < 0) && (errno != EAGAIN) ) {
         fprintf(stderr,"POLL died!\n");
         return 1; 
     }  
     /* we got at least one readable socket... try to service them */
     int target = 0;
     for(int i = 0; i < njobs ; ++i) {
         int ready = pfds[i].revents & (POLLIN|POLLHUP);
         int more  = fname_idx < argc;
         if(!ready || more) {
             /* keep this fd in the list */
                 if(target != i) {
                    pfds[target] = pfds[i];
                    jobs[target] = jobs[i];
                 }
                 target++;
         }

         if(ready) {
             nerr += handle_input(pfds[i].fd);
             if(more) {
                 nerr += serve_file(jobs[i].fd_to, argv[fname_idx++]);
             } else { 
                 /* we are out of files... close down the child */
                 close(jobs[i].fd_to);
                 close(jobs[i].fd_from);
             }
         }
     }
     njobs = target; 
  }

  if(nerr > 0) {
     fprintf(stderr,"There were %d errors.\n",nerr);
  }
  return (nerr==0)?0:1;
}
