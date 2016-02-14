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
#include<stdarg.h>

/* read unbuffered line from pipes */
static ssize_t read_line(int fd, char *buf, size_t sz) {
  ssize_t total = 0;
  --sz; /* account for the '\0' */
  ssize_t rsz = read(fd,buf,sz);
  total = rsz; 

  while((rsz > 0) && (buf[rsz-1] != '\n'))  {
        buf   += rsz;  
	sz    -= rsz;  
        rsz = read(fd,buf,sz);
        total += rsz;
  }
     
  if(rsz < 0) return rsz;
  
  buf[rsz] = '\0';
  return total;
}

/* write unbuffered line to pipes */
static ssize_t write_line(int fd, const char* fmt, ...) {
  static char buffer[1024];

  va_list ap;
  va_start(ap, fmt);
  size_t len = vsnprintf(buffer,1023,fmt,ap);

  /* end it with a newline if the client didn't */
  if(buffer[len-1] != '\n')  {
     buffer[len++] = '\n';
     buffer[len] = '\0';
  }
  
  const char *buf = buffer;
  ssize_t answer = (ssize_t)len;
  ssize_t rsz = 0;
  while(len > 0) { 
     rsz = write(fd,buf,len);
     if(rsz < 0) break;
     len -= rsz;
     buf += rsz;
  }
  
  return (rsz < 0)  ? rsz : answer; 
}


enum { P_READ, P_WRITE } ;

static void print_hash(char *buf, size_t bytes, const uint8_t*const hash) {
  for(size_t v = 0; v < bytes; ++v) {
     sprintf(buf,"%02x",hash[v]);
     buf += 2;
  } 
  *buf = '\0';
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
static void run_job(int hash_sz, int readfd, int writefd) {
     char fname[1024];
     uint8_t * const hashbuf = malloc(hash_sz * sizeof(uint8_t) + 1);
     if(hashbuf == NULL) panic("Can't allocate hash buffer!");

     if(write_line(writefd,"OK") < 0) return;

     ssize_t flen;
     while ( (flen = read_line(readfd, fname, sizeof(fname))) > 0 )
     {
        /* chop of the newline */
	fname[flen - 1] = '\0'; 

        FILE *input = fopen(fname,"rb");
        if(input != NULL) {
          setvbuf(input, NULL, _IONBF, 0);
          const uint8_t *const hash = spritz_file_hash(hash_sz,input);
          fclose(input);

          if(hash == NULL) {
            write_line(writefd,"ER Could not hash <%s>", fname);
	    continue;
	  }

	  print_hash(hashbuf, hash_sz, hash);
	  write_line(writefd, "OK %s: %s",fname,hashbuf);

          destroy_spritz_hash(hash);
        } else {
          write_line(writefd,"ER Could not open <%s>",fname);
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
	/* we are the child... close the unused channels */
        close(pipe1[P_WRITE]);
        close(pipe2[P_READ]);
        /* process requests */
	run_job(hash_sz, pipe1[P_READ], pipe2[P_WRITE]); 
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
  int sz = 32;
  int njobs = 1;
  int child_mode = 0;

  while ( (c = getopt(argc,argv,"hs:j:c")) != -1 ) {
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
     case 's':
        sz = (atoi(optarg) + 7) / 8;
        if(sz < 1) sz = 1;
	break;
     } 
  }

  if(child_mode == 1) {
      if(optind != argc) { usage(); }
      run_job(sz,0,1);
      exit(0);
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
