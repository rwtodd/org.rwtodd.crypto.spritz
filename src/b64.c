#include<stdint.h>
#include<stddef.h>
#include<stdlib.h>
#include<stdbool.h>

/*
 * base 64 requires 4/3 the number of bytes as the input, rounded up.
 * This function tells you how many bytes of space you need for a 
 * null-terminated base-64 transformation if the input has size
 * `insize`.
 */
size_t
base64_outsize (size_t insize)
{
  return (insize + 2) / 3 * 4 + 1;
}

/* base64_encode allocates a buffer and encodes the given array in base64.
 * The result buffer is expected to be at least as large as
 * `base64_outsize(len)`, and this function null-terminates the value.
 */
void
base64_encode (const uint8_t * in, size_t len, char *result)
{
  static const char letters[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char remainder;               /* temp var for leftover bits during processing */
  while (len >= 3)
    {
      *result++ = letters[((*in) >> 2) & 63];   /* top 6 bits */
      remainder = (*in++ & 3);
      *result++ = letters[(remainder << 4) | (((*in) >> 4) & 15)];      /* bottom 2 bits plus top 4 bits */
      remainder = (*in++ & 15);
      *result++ = letters[(remainder << 2) | (((*in) >> 6) & 3)];       /* bottom 4 bits plus top 2 bits */
      *result++ = letters[(*in++ & 63)];
      len -= 3;
    }

  switch (len)
    {
    case 0:
      break;
    case 1:
      *result++ = letters[((*in) >> 2) & 63];   /* top 6 bits */
      *result++ = letters[((*in) & 3) << 4];    /* bottom 2 bits plus zero bits */
      *result++ = '=';
      *result++ = '=';
      break;
    case 2:
      *result++ = letters[((*in) >> 2) & 63];   /* top 6 bits */
      remainder = (*in++ & 3);
      *result++ = letters[(remainder << 4) | (((*in) >> 4) & 15)];      /* bottom 2 bits plus top 4 bits */
      *result++ = letters[(*in & 15) << 2];     /* bottom 4 bits  plus zero bits */
      *result++ = '=';
    }

  *result = '\0';
}
