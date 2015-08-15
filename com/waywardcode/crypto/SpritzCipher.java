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
    i=0; j=0; k=0; z=0; a=0;
    w=1;
    s = new byte[256];
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
     whip(512);
     crush();
     whip(512);
     crush();
     whip(512);
     a = 0;
  }

  private static int GCD(final int e1, final int e2) {
     if (e2 == 0) { return  e1; }  else { return GCD(e2, e1 % e2); }
  }

  private void whip(final int r) {
    for(int idx = 0; idx < r; ++idx) { update(); }
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
    * @param end the end of the range to transform, exclusive 
    * @return the transformed array
    */
  public void squeezeXOR(final byte[] buf, final int start, final int end) {
    if (a > 0) { shuffle(); }
    for(int idx = start; idx < end; ++idx) {
       buf[idx] = (byte)(buf[idx] ^ dripOne());
    }
  }

  /** Like squeeze, but XORs into the existing buffer.
    * Obviously this is here to encrypt or decrypt 
    * arrays of data.
    * @param buf a buffer of data to encrypt/decrypt 
    *   against the cipher stream.
    * @return the transformed array
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

  private void update() {
     i = (i + w) & 0xff ;
     final int si = s[i] & 0xff ;
     final int sjsi = s[ (j + si) & 0xff ] & 0xff ;
     j = ( k + sjsi ) & 0xff  ;
     final int sj = s[j] & 0xff ;
     k = ( i + k + sj ) & 0xff ;
     swap(i,j);
  }

  private int dripOne() {
     update();
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
     byte[] pwhash;

     try {
       pwhash  = hash(256, key.getBytes("UTF-8"));
     } catch(Exception e) {
        System.err.println(e.toString());
        pwhash = hash(256, key.getBytes());
     }

     SpritzCipher encStream = new SpritzCipher();
     encStream.absorb(pwhash);
     if(iv != null) {
        encStream.absorbStop();
        encStream.absorb(iv);
     }
     return encStream;
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
    */
  public static byte[] hash(final int bits, final java.io.InputStream instr) 
    throws java.io.IOException {
     final SpritzCipher hasher = new SpritzCipher();
     final int bytes = (bits + 7)/8;
     final byte[]  buffer = new byte[4096];

     int count = instr.read(buffer) ;
     while(count >= 0) {
        hasher.absorb(buffer,0,count);
        count = instr.read(buffer);
     }

     hasher.absorbStop();
     hasher.absorb( (byte)bytes );
     return hasher.squeeze(bytes);
  }

  /** XORs a cipher with an input stream, writing an output stream. 
    * Note that 
    * the method reads until no more data is available, but
    * it doesn't close the stream.
    * @param instr the data to encrypt/decrypt.
    * @param outstr the stream where the output is written.
    */
  public void combine(final java.io.InputStream instr,
                      final java.io.OutputStream outstr) 
     throws java.io.IOException {
      final byte[] buffer = new byte[4096];
 
      int count = instr.read(buffer) ;
      while(count >= 0) {
         squeezeXOR(buffer,0,count);
         outstr.write(buffer,0,count);
         count = instr.read(buffer);
      }
   }

  /** Encrypt an input stream with a password.
    * This method creates a 4-byte random initialization
    * vector, and writes that to the output unencrypted.
    * It then encrypts 4 random bytes, and the 32-bit hash
    * of those bytes.  This way, upon decryption, we can
    * tell immediately if we are using the correct password
    * (since it would be highly unlikely to get the correct
    * hash if we had the wrong spritz stream). 
    * Finally, the data from the input is combined with the
    * cipher stream and written out.
    * @param key the password to use. It is converted to UTF-8 bytes.
    * @param instr the source of the data to encrypt.
    * @param outstr where the output is written.
    */
  public static void encrypt(final String key,
                             final java.io.InputStream instr, 
                             final java.io.OutputStream outstr) 
    throws java.io.IOException {

     final java.util.Random rnd = new java.util.Random(System.currentTimeMillis());
     final byte[] iv = new byte[4];
     rnd.nextBytes(iv);

     final SpritzCipher cipher = cipherStream(key, iv);

     // first, write the iv..
     outstr.write(iv);

     // now, write 4 random bytes, and a hash of them...
     // so we can tell if we have the right password
     // on decryption
     final byte[] randomBytes = new byte[4];
     rnd.nextBytes(randomBytes);
     final byte[] hashedBytes = hash(32,randomBytes);
     cipher.squeezeXOR(randomBytes);
     cipher.squeezeXOR(hashedBytes);
     outstr.write(randomBytes);
     outstr.write(hashedBytes);

     // now just write the encrypted stream...
     cipher.combine(instr, outstr);

  }

  private static int readFully(final java.io.InputStream instr,
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

  /** Decrypt an input stream with a password.
    * This method reads a 4-byte random initialization
    * vector, and creates a cipher stream with the IV and
    * the given key.  It then decrypts 4 bytes, and creates
    * 32-bit hash of those bytes.  If the next 4 decrypted
    * bytes match the hash, we assume we have the correct
    * decryption stream.  At this point we decrypt
    * the rest of the bytes from the input stream, and write
    * the results to the output stream.
    * @param key the password to use. It is converted to UTF-8 bytes.
    * @param instr the source of the data to decrypt.
    * @param outstr where the output is written.
    */
  public static void decrypt(final String key, 
                             final java.io.InputStream instr, 
                             final java.io.OutputStream outstr) 
    throws java.io.IOException {
     
     final byte[] iv = new byte[4];
     if( readFully(instr, iv) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough to contain an IV!");
     }

     final SpritzCipher cipher = cipherStream(key, iv);

     // now verify the random bytes and their hash...
     final byte[] randomBytes = new byte[4];
     if( readFully(instr, randomBytes) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough for a header!");
     }
     final byte[] randomHash = new byte[4];
     if( readFully(instr, randomHash) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough for a header!");
     }
     cipher.squeezeXOR(randomBytes);
     cipher.squeezeXOR(randomHash); 
     final byte[] testHash = hash(32,randomBytes);
     if( !java.util.Arrays.equals(testHash,randomHash) ) {
         throw new IllegalStateException("Bad Password or corrupted file!");
     } 

     // now decrypt the rest of the bytes, which
     // is the data payload
     cipher.combine(instr, outstr) ;
  }

}

