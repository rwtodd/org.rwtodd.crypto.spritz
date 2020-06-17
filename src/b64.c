#include<stdint.h>
#include<stddef.h>
#include<stdlib.h>

/* base64_encode allocates a buffer and encodes the given array in base64.
 * The caller is required to `free()` the returned buffer.  The buffer
 * is null-terminated.
 */
char *base64_encode(const uint8_t *in, size_t len) {
   static const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   if(len == 0) return NULL;

   char *const ans = malloc( (len + 2) / 3 * 4 + 1);
   char * out = ans;

   char remainder;  /* temp var for leftover bits during processing */
   while(len >= 3) {
      *out++ = letters[((*in)>>2) & 63];     /* top 6 bits */
      remainder = (*in++ & 3); 
      *out++ = letters[(remainder << 4) | (((*in)>>4) & 15)];   /* bottom 2 bits plus top 4 bits */
      remainder = (*in++ & 15);
      *out++ = letters[(remainder << 2) | (((*in)>>6) & 3)];    /* bottom 4 bits plus top 2 bits */
      *out++ = letters[(*in++ & 63)];
      len -= 3;
   }
   
   switch(len) {
      case 0:
          break;
      case 1:
          *out++ = letters[((*in)>>2) & 63];     /* top 6 bits */
          *out++ = letters[((*in)&3) << 4];      /* bottom 2 bits plus zero bits */
          *out++ = '=';
          *out++ = '=';
          break;
      case 2:
         *out++ = letters[((*in)>>2) & 63];     /* top 6 bits */
         remainder = (*in++ & 3); 
         *out++ = letters[(remainder << 4) | (((*in)>>4) & 15)];   /* bottom 2 bits plus top 4 bits */
         *out++ = letters[(*in & 15) << 2];  /* bottom 4 bits  plus zero bits */
         *out++ = '=';
   }

   *out = '\0';
   return ans;
}
