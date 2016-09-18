/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;


import java.io.InputStream;
import java.io.IOException;
import java.io.FilterInputStream;
import java.util.Optional;
import static com.waywardcode.crypto.SpritzUtils.*;

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

     SpritzHeader header = new SpritzHeader();
     header.Read(in, key);
     
     byte[] payloadKey = header.getPayloadKey();
     
     // now use the key as the basis for further decryption...
     cipher = new SpritzCipher();
     cipher.absorb(payloadKey);
     cipher.skip(2048 + (payloadKey[3]&0xFF));
     
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
  

  /** Reads a single byte.
    * @return the decrypted byte.
    * @throws IOException when there's a problem with the read
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
    cipher.skip(n);
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

