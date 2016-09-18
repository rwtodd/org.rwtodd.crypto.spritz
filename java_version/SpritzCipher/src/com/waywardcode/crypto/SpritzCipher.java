/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;


/** Implements the Spritz stream cipher. 
  * This class does the actual calculation, and
  * encapsulates the internal spritz state. 
  * Static methods are provided as 
  * helper functions to cover common uses.
  * @author Richard Todd
  */
public class SpritzCipher {
  private int i,j,k,z,a,w;  // these are terrible names,
                            // but match the RS14.pdf description
  private final byte[] s;

  public SpritzCipher() {
    s = new byte[256];
    reset();
  }

  /** Resets the cipher for re-use.
   * @author Richard Todd.
   */
  public void reset() {
    i=0; j=0; k=0; z=0; a=0;
    w=1;
    for(int idx = 0; idx < s.length; ++idx) {
       s[idx] = (byte)idx;
    }      
  }
  
  /** Abosrb a single byte. 
    * @param b the byte to absorb.
    */
  public void absorb(final byte b) {
     absorbNibble( b & 0x0F );        // low bits
     absorbNibble( (b & 0xFF) >> 4 ); // high bits
  }

  /** Abosrb an array of bytes. 
    * @param bs the bytes to absorb.
    */
  public void absorb(final byte[] bs) { for(final byte b: bs) { absorb(b); } }

  /** Abosrb an array of bytes. 
    * @param bs the bytes to absorb.
    * @param start the first index of the array to absorb
    * @param end the end of the range to absorb, exclusive 
    */
  public void absorb(final byte[] bs, final int start, final int end) { 
    for(int idx = start; idx < end; ++idx) {
      absorb(bs[idx]);
    }
  }

  private void swap(final int e1, final int e2) {
     final byte tmp = s[e1] ; s[e1] = s[e2] ; s[e2] = tmp;
  }

  private void absorbNibble(final int x)  {
    if (a == 128) { shuffle(); }
    swap(a, 128 + x);  // no need for mod here due to nibble size
    a += 1;
  }

  /** Inserts a separator between absorbed sources. 
    * Use this, for example, between the encryption 
    * key and the initialization vector.
    */ 
  public void absorbStop() {
    if (a == 128) { shuffle(); }
    a += 1;
  } 

  private void shuffle() {
     whip();
     crush();
     whip();
     crush();
     whip();
     a = 0;
  }

  private static int GCD(final int e1, final int e2) {
     if (e2 == 0) { return  e1; }  else { return GCD(e2, e1 % e2); }
  }

  private void whip() {
    update(512);
    do { 
      w = (w + 1) & 0xff;
    } while(GCD(w,256) != 1);
  } 

  private void crush() {
     for(int v = 0; v < 128; ++v) {
       if( (s[v] & 0xff) > (s[256 - 1 - v] & 0xff) ) {
          swap(v, 256 - 1 - v);
       }
     }
  }

  /** Fill buf with cipher bytes. This should only
    * be called after one or more calls to absorb. 
    * @param buf the array to overwrite with the cipher stream.
    * @return the transformed array
    */
  public byte[] squeeze(final byte[] buf) {
    if (a > 0) { shuffle(); }
    for(int idx = 0; idx < buf.length; ++idx) {
       buf[idx] = (byte)dripOne(); 
    }
    return buf;
  }

  /** Create an array of cipher bytes. This should only
    * be called after one or more calls to absorb. 
    * @param count the number of bytes to squeeze 
    * @return a newly-created array of bytes from the cipher
    */
  public byte[] squeeze(final int count) {
    return squeeze( new byte[count] );
  } 
  
  /** Like squeeze, but XORs into the existing buffer.
    * Obviously this is here to encrypt or decrypt 
    * arrays of data.
    * @param buf a buffer of data to encrypt/decrypt 
    *   against the cipher stream.
    * @param start the first index of the array to transform 
    * @param len the length of the range to transform
    */
  public void squeezeXOR(final byte[] buf, final int start, int len) {
    if (a > 0) { shuffle(); }
    len = start + len;
    for(int idx = start; idx < len; ++idx) {
       buf[idx] = (byte)(buf[idx] ^ dripOne());
    }
  }

  /** Like squeeze, but XORs into the existing buffer.
    * Obviously this is here to encrypt or decrypt 
    * arrays of data.
    * @param buf a buffer of data to encrypt/decrypt 
    *   against the cipher stream.
    */
  public void squeezeXOR(final byte[] buf) { squeezeXOR(buf, 0, buf.length); }

  /** Generate a single random byte. Only to be
    * used after one or more calls to absorb.
    * @return the next byte from the cipher stream
    */
  public byte drip() {
    if (a > 0) { shuffle(); }
    return (byte)dripOne();
  }

  private void update(int amt) {
    int mi = i & 0xff;
    int mj = j & 0xff;
    int mk = k & 0xff;
    final int mw = w & 0xff;

    while(amt-- > 0) {
      mi = (mi + mw) & 0xff;
      final int si = s[mi] & 0xff;
      mj =  (mk + (s[ (mj + si) & 0xff ] & 0xff)) & 0xff;
      final int sj = s[mj] & 0xff;
      mk = ( mi + mk + sj ) & 0xff ;
      s[mi] = (byte)sj;
      s[mj] = (byte)si;
    }

    i = mi;
    j = mj;
    k = mk;
  }

  private int dripOne() {
     update(1);
     final int step1 = s[ (z + k) & 0xff ] & 0xff ;
     final int step2 = s[ (i + step1) & 0xff ] & 0xff ;
     z =  s[ (j + step2) & 0xff ] & 0xff ;
     return z;  
  }

  /** Create a spritz cipher stream for a given key and initialization vector.
    * @param key a string containing the password. It is converted to UTF-8 bytes.
    * @param iv  an array of bytes to use for an initialization vector.  If null,
    *           the cipher won't use an initialization vector.
    * @return an initialized SpritzCipher instance, ready to produce bytes. 
    */
  public static SpritzCipher cipherStream(final String key, final byte[] iv) {
     SpritzCipher initSpritz = new SpritzCipher();

     byte[] keyBytes;
     try {
       keyBytes  = hash(512, key.getBytes(java.nio.charset.StandardCharsets.UTF_8));
     } catch(Exception e) {
        System.err.println(e.toString());
        keyBytes = hash(512, key.getBytes());
     }

     int iterations = 20000 + (iv[3] & 0xFF);
     for(int i = 0; i < iterations; ++i) {
         initSpritz.reset();
         initSpritz.absorb(iv);
         initSpritz.absorbStop();
         initSpritz.absorb(keyBytes);
         initSpritz.squeeze(keyBytes);
         iv[0] = (byte)((iv[0] & 0xFF) + 1);
         if(iv[0] == 0) {
             iv[1] = (byte)((iv[1] & 0xFF) + 1);
             if(iv[1] == 0) {
                iv[2] = (byte)((iv[2] & 0xFF) + 1);
                if(iv[2] == 0) {
                    iv[3] = (byte)((iv[3] & 0xFF) + 1);                
                }
             }
         }
     }
     
     initSpritz.reset();
     initSpritz.absorb(keyBytes);
     return initSpritz;
  }

  /** Utility function to XOR two byte arrays */
  public static void XORInto(byte[] dest, byte[] src) {
      for(int i = 0; i< dest.length; i++) {
          dest[i] ^= src[i];
      }
  } 
  
  /** Hash an array of bytes. Can create a hash of as many bits
    * as required, rounded up to a byte boundary.
    * @param bits how many bits wide to make the hash.
    * @param data the data to hash.
    * @return the hash
    */
  public static byte[] hash(final int bits, final byte[] data) {
     final int bytes = (bits + 7)/8;
     final SpritzCipher hasher = new SpritzCipher();
     hasher.absorb(data);
     hasher.absorbStop();
     hasher.absorb( (byte)bytes );
     return hasher.squeeze(bytes);
  }

  /** Hash an input stream. Can create a hash of as many bits
    * as required, rounded up to a byte boundary.  Note that 
    * the method reads until no more data is available, but
    * it doesn't close the stream.
    * @param bits how many bits wide to make the hash.
    * @param instr the data to hash.
    * @return the hash
    * @throws java.io.IOException if there is a problem with the IO
    */
  public static byte[] hash(final int bits, final java.io.InputStream instr) 
    throws java.io.IOException {
        
     final SpritzCipher hasher = new SpritzCipher();
     final int bytes = (bits + 7)/8;
     final byte[]  buffer = new byte[4096];

     int count = 0;
     while(count >= 0) {
        count = instr.read(buffer);
        hasher.absorb(buffer,0,count);
     }

     hasher.absorbStop();
     hasher.absorb( (byte)bytes );
     return hasher.squeeze(bytes);
  }
  
}

