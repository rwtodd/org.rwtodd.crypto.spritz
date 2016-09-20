/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;

import java.io.InputStream;

/**
 * A static class of utility methods.
 * @author richard
 */
public class SpritzUtils {
    
    /** 
     * convert an integer into a big-endian array of component bytes, absorbing
     * it into the given spritz sponge.  It would take an obscenely-large hash
     * to need more than 2 bytes, so this recursive implementation should be
     * ok.  It's the cleanest-looking version of the algorithm I could derive,
     * without building a stack-like collection of bytes.
     * @param c The cipher to use
     * @param n The value to split into bytes
     */
    public static void absorbIntBytes(SpritzCipher c, int n) {
         if(n <= 255) {
             c.absorb((byte)n);
         } else {      
            absorbIntBytes(c, (n >> 8));
            c.absorb((byte)(n & 0xff));
         }
    }
    
    
   /**
    * Read enough bytes to fill the buffer, or until the end 
    * of the stream, whichever comes first.
    * @param instr The input stream to use
    * @param buffer The buffer to fill
    * @return the number of bytes read
    * @throws java.io.IOException if the underlying read fails
    */
   public static int readFully(final InputStream instr,
                               final byte[] buffer) 
    throws java.io.IOException {

      int total = buffer.length;
      int offset = 0;

      while( total > 0 ) {
         int amount = instr.read(buffer, offset, total);
         if (amount >= 0) {
           offset += amount;
           total -= amount;
         } else {
            total = 0;
         }
      } 
      return offset;
  }
     
  /** Utility function to XOR two byte arrays
     * @param dest destination array
     * @param src  source array
   */
  public static void XORInto(byte[] dest, byte[] src) {
      for(int i = 0; i< dest.length; i++) {
          dest[i] ^= src[i];
      }
  }   
  
}
