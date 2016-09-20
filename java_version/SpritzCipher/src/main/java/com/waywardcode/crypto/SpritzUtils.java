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
