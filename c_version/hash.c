/* let's make a quick c-version of
 * the hasher, and see how it compares
 * to the other versions, speed-wise.
 */

#include "spritz.h"
#include<stdint.h>
#include<stdio.h>
#include<signal.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<poll.h>
#include<errno.h>

enum { P_READ, P_WRITE } ;

static void print_hash(size_t bytes, const uint8_t*const hash) {
  for(size_t v = 0; v < bytes; ++v) {
     printf("%02x",hash[v]);
  } 
}

static void usage() {
  fprintf(stderr,"Usage: spritz-hash [options] file1 file2...\n");
  fprintf(stderr,"  -h    Display this help message.\n");
  fprintf(stderr,"  -s n  Set the hash size to n bits\n");
  fprintf(stderr,"  -j n  Run n hashes at once.\n");
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
static void run_job(int hash_sz) {
     char fname[384];

     printf("OK\n"); /* request input */
     fflush(stdout);

     while (fgets(fname, sizeof(fname), stdin) != 0)
     {
        /* chop of the newline */
	fname[strlen(fname) - 1] = '\0'; 

        FILE *input = fopen(fname,"rb");
        setvbuf(input, 0, _IONBF, 0);
        if(input != NULL) {
          const uint8_t *const hash = spritz_file_hash(hash_sz,input);
          fclose(input);

          if(hash == NULL) {
            printf("ER <%s> could not hash\n", fname);
            fflush(stdout);
	    continue;
	  }
	  printf("OK %s: ",fname);
          print_hash(hash_sz,hash);
          printf("\n");
          fflush(stdout);
          destroy_spritz_hash(hash);

        }
	else {
          printf("ERR <%s> BAD FILE\n",fname);
          fflush(stdout);
        }
     }
}

static job* create_jobs(int num, int hash_sz) {
  job *ans = malloc(num*sizeof(job));
  if(ans == NULL) panic("Out of memory!");

  for(int idx = 0 ; idx < num; ++idx) {
     int pipe1[2]; /* parent -> child */
     int pipe2[2]; /* child -> parent */
     if( pipe(pipe1) != 0 ) panic("Can't create pipe!");
     if( pipe(pipe2) != 0 ) panic("Can't create pipe!");
     if((ans[idx].pid = fork()) < 0) panic("Can't fork!");

     if(ans[idx].pid == 0) {
	/* we are the child... set stdin to pipe1 and pipe2 to stdout */
        close(pipe1[P_WRITE]);
        close(pipe2[P_READ]);
        dup2(pipe1[P_READ], STDIN_FILENO);
        close(pipe1[P_READ]);
        dup2(pipe2[P_WRITE], STDOUT_FILENO);
        close(pipe2[P_WRITE]);  
        /* process requests */
	run_job(hash_sz); 
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
  char inbuf[512];
  int errs = 0;

  size_t rsz = read(fd,inbuf,512);
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
  char outbuf[512];
  strncpy(outbuf,fname,510);
  size_t flen = strlen(fname);
  if(flen > 510) return 1;
  outbuf[flen] = '\n';
  outbuf[flen+1] = '\0';

  if(write(fd,outbuf,flen+1) < 0) return 1;

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
  int sz = 32;
  int njobs = 1;

  while ( (c = getopt(argc,argv,"hs:j:")) != -1 ) {
     switch(c) {
     case 'h':
	usage();
	break;
     case 'j':
        njobs = atoi(optarg);
        if(njobs < 1) njobs = 1;
	break;
     case 's':
        sz = (atoi(optarg) + 7) / 8;
        if(sz < 1) sz = 1;
	break;
     } 
  }
  if(argc <= optind) { usage(); }

  /* set up concurrency */
  job *jobs = create_jobs(njobs,sz);
  int nerr = 0;

  /* set up for poll() */
  struct pollfd pfds[njobs];
  for(int idx = 0; idx < njobs; ++idx) {
     pfds[idx].fd = jobs[idx].fd_from;
     pfds[idx].events = POLLIN|POLLHUP;
  }

  /* serve jobs */
  int idx = optind;
  while(idx < argc) {
     /* poll for available child */
     int num_events = poll(pfds, njobs, -1);
     if(num_events == 0) {
         continue;
     } else if( (num_events < 0) && (errno != EAGAIN) ) {
         fprintf(stderr,"POLL died!\n");
	 return 1; 
     }  
     /* we got at least one readable socket... try to serve them */
     for(int j = 0; j < njobs ; ++j) {
         if(pfds[j].revents & (POLLIN|POLLHUP)) {
             nerr += handle_input(pfds[j].fd);
	     nerr += serve_file(jobs[j].fd_to, argv[idx++]);
	     if(idx == argc) break;
	 }
     }
  }

  /* now cleanup */
  for(int j = 0; j < njobs; ++j) {
     close(jobs[j].fd_to);
     nerr += handle_input(pfds[j].fd);
  }

  return (nerr==0)?0:1;
}
