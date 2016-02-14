/* just a couple line-io helper functions */

#include "lineio.h"
#include<unistd.h>
#include<stdarg.h>
#include<stdio.h>

/* read ubuffered line from pipes */
ssize_t read_line(int fd, char *buf, size_t sz) {
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
ssize_t write_line(int fd, const char* fmt, ...) {
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

