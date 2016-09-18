/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;


import java.io.InputStream;
import java.io.IOException;
import java.io.FilterInputStream;
import java.util.Arrays;
import java.util.Optional;

/** Implements an encrypted input stream via the Spritz stream cipher. 
  * This class uses SpritzCipher for all the heavy lifting.
  * @author Richard Todd
  */
public class SpritzInputStream extends FilterInputStream  {
  private final SpritzCipher cipher;
  private final Optional<String> fname;

  /** Constructs an encrypted stream.
    * This method reads a 4-byte random initialization
    * vector, and creates a cipher stream with the IV and
    * the given key.  It then decrypts 4 bytes, and creates
    * 32-bit hash of those bytes.  If the next 4 decrypted
    * bytes match the hash, we assume we have the correct
    * decryption stream. 
    * @param key the password to use. It is converted to UTF-8 bytes.
    * @param in the earlier InputStream in the chain.
    * @throws java.io.IOException if there is a problem reading from 'in'
    */
  public SpritzInputStream(final String key, final InputStream in) 
    throws IOException
  {
     super(in);

     final byte[] iv = new byte[4];
     
     if( readFully(in, iv) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!");
     }
     
     SpritzCipher.XORInto(iv,  SpritzCipher.hash(32, key.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
 
     cipher = SpritzCipher.cipherStream(key, iv);

     /* now decrypt the rest of the header */
     byte[] header = new byte[72];
     if( readFully(in, header) != 72 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!");
     }
     cipher.squeezeXOR(header,0,4);
     for(int i = 0; i < (header[3] & 0xFF); i++) { cipher.drip(); }
     cipher.squeezeXOR(header, 4, 68); 
     
     // now verify the random bytes and their hash...
     final byte[] randomBytes = Arrays.copyOfRange(header,0,4);
     final byte[] randomHash = Arrays.copyOfRange(header,4,8);
     final byte[] testHash = SpritzCipher.hash(32,randomBytes);
     if( !java.util.Arrays.equals(testHash,randomHash) ) {
         throw new IllegalStateException("Bad Password or corrupted file!");
     } 
    
     // now use the key as the basis for further decryption...
     cipher.reset();
     cipher.absorb(header, 8, 72);
     for(int i = 0; i < (2048+(header[11] & 0xFF)); i++) { 
         cipher.drip();
     }
     
     int fnamelen = in.read();
     if (fnamelen == -1) {
         throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!");
     }
     fnamelen  ^= (cipher.drip() & 0xFF);     
     if( fnamelen > 0 ) {
        final byte[] fnameBytes = new byte[fnamelen];
        if( readFully(in, fnameBytes) != fnamelen ) {
            throw new IllegalStateException("Instream corrupted!");
        }
        cipher.squeezeXOR(fnameBytes);
        fname = Optional.of(new String(fnameBytes,"UTF-8"));
     } else {
        fname = Optional.empty();
     }
    
  }

  /** Retrieves the filename that was stored in the encrypted stream.
     * @return the embedded filename */
  public Optional<String> getFname() { return fname; }
  
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
    * @param len the maximum amount of bytes to read.
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

