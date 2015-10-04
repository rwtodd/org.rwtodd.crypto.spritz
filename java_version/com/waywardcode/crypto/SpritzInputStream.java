// The Spritz Cipher
// This implementation is copyright 2015 Richard Todd

//   This program is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 2 of the License, or
//   (at your option) any later version.
// 
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
// 
//   You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <http://www.gnu.org/licenses/>.

package com.waywardcode.crypto;


import java.io.InputStream;
import java.io.IOException;
import java.io.FilterInputStream;

/** Implements an encrypted input stream via the Spritz stream cipher. 
  * This class uses SpritzCipher for all the heavy lifting.
  * @author Richard Todd
  */
public class SpritzInputStream extends FilterInputStream  {
  private final SpritzCipher cipher;

  /** Constructs an encrypted stream.
    * This method reads a 4-byte random initialization
    * vector, and creates a cipher stream with the IV and
    * the given key.  It then decrypts 4 bytes, and creates
    * 32-bit hash of those bytes.  If the next 4 decrypted
    * bytes match the hash, we assume we have the correct
    * decryption stream. 
    * @param key the password to use. It is converted to UTF-8 bytes.
    * @param in the earlier InputStream in the chain.
    */
  public SpritzInputStream(final String key, final InputStream in) 
    throws IOException
  {
     super(in);

     final byte[] iv = new byte[4];
     if( readFully(in, iv) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough to contain an IV!");
     }

     cipher = SpritzCipher.cipherStream(key, iv);

     // now verify the random bytes and their hash...
     final byte[] randomBytes = new byte[4];
     if( readFully(in, randomBytes) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough for a header!");
     }
     final byte[] randomHash = new byte[4];
     if( readFully(in, randomHash) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough for a header!");
     }
     cipher.squeezeXOR(randomBytes);
     cipher.squeezeXOR(randomHash); 
     final byte[] testHash = SpritzCipher.hash(32,randomBytes);
     if( !java.util.Arrays.equals(testHash,randomHash) ) {
         throw new IllegalStateException("Bad Password or corrupted file!");
     } 

  }

  private static int readFully(final InputStream instr,
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


  /** Reads a single byte.
    * @return the decrypted byte.
    */
  @Override
  public int read() throws IOException {
     return in.read() ^ cipher.drip();
  }
 
  /** Reads a series of bytes.
    * @param b the buffer to read into.
    * @param off offset into the buffer.
    * @param the maximum amount of bytes to read.
    * @return the number of bytes read.
    */
  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    int amt = in.read(b,off,len);
    cipher.squeezeXOR(b,off,amt);
    return amt; 
  } 

  /** Skips over some input bytes.
    * @param n the number of bytes to skip.
    * @return the actual number skipped (may be less than n)
    */
  @Override
  public long skip(long n) throws IOException {
    long ans = in.skip(n);
    for(long idx = 0; idx < ans; ++idx) { cipher.drip(); }
    return ans;
  }


  /** Throws an exception since we don't support mark/reset.
    */
  @Override
  public void reset() throws IOException {
    throw new IOException("mark/reset not supported on SpritzInputStreams!");
  }

  /** Returns false since we don't support mark/reset. 
    * @return false.
    */
  @Override
  public boolean markSupported() { return false; }

}

