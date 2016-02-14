#pragma once

/* just a couple line-io helper functions */
#include<sys/types.h>

/* read unbuffered line from pipes */
ssize_t read_line(int fd, char *buf, size_t sz);

/* write unbuffered line to pipes */
ssize_t write_line(int fd, const char* fmt, ...);
