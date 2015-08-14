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
  * A companion object is provided with
  * helper functions for use in common cases.
  * @author Richard Todd
  */
public class SpritzCipher {
  private int i,j,k,z,a,w;  // these are terrible names,
                            // but match the RS14.pdf description
  private byte[] s;

  public SpritzCipher() {
    i = 0; j=0; k=0;z=0;a=0;
    w=1;
    s = new byte[256];
    for(int idx = 0; idx < s.length; ++idx) {
       s[idx] = (byte)idx;
    }
  }

  /** Abosrb a single byte. 
    * @param b the byte to absorb.
    */
  public void absorb(byte b) {
     absorbNibble( b & 0x0F );        // low bits
     absorbNibble( (b & 0xFF) >> 4 ); // high bits
  }

  /** Abosrb a sequence of bytes. 
    * @param bs the bytes to absorb.
    */
  public void absorb(byte[] bs) { for(byte b: bs) { absorb(b); } }
  public void absorb(byte[] bs, int start, int end) { 
    for(int idx = start; idx < end; ++idx) {
      absorb(bs[idx]);
    }
  }

  private void swap(int e1, int e2) {
     byte tmp = s[e1] ; s[e1] = s[e2] ; s[e2] = tmp;
  }

  private void absorbNibble(int x)  {
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

  private static int GCD(int e1, int e2) {
     if (e2 == 0) { return  e1; }  else { return GCD(e2, e1 % e2); }
  }

  private void whip(int r) {
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
  public byte[] squeeze(byte[] buf) {
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
  public byte[] squeeze(int count) {
    return squeeze( new byte[count] );
  } 
  
  /** Like squeeze, but XORs into the existing buffer.
    * Obviously this is here to encrypt or decrypt 
    * arrays of data.
    * @param buf a buffer of data to encrypt/decrypt 
    *   against the cipher stream.
    * @return the transformed array
    */
  public void squeezeXOR(byte[] buf, int start, int end) {
    if (a > 0) { shuffle(); }
    for(int idx = start; idx < end; ++idx) {
       buf[idx] = (byte)(buf[idx] ^ dripOne());
    }
  }
  public void squeezeXOR(byte[] buf) { squeezeXOR(buf, 0, buf.length); }

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
     int si = s[i] & 0xff ;
     int sjsi = s[ (j + si) & 0xff ] & 0xff ;
     j = ( k + sjsi ) & 0xff  ;
     int sj = s[j] & 0xff ;
     k = ( i + k + sj ) & 0xff ;
     swap(i,j);
  }

  private int dripOne() {
     update();
     int step1 = s[ (z + k) & 0xff ] & 0xff ;
     int step2 = s[ (i + step1) & 0xff ] & 0xff ;
     z =  s[ (j + step2) & 0xff ] & 0xff ;
     return z;  
  }

  public static SpritzCipher cipherStream(String key, byte[] iv) {
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

  public static byte[] hash(int bits, byte[] data) {
     int bytes = (bits + 7)/8;
     SpritzCipher hasher = new SpritzCipher();
     hasher.absorb(data);
     hasher.absorbStop();
     hasher.absorb( (byte)bytes );
     return hasher.squeeze(bytes);
  }

  public static byte[] hash(int bits, java.io.InputStream instr) 
    throws java.io.IOException {
     SpritzCipher hasher = new SpritzCipher();
     int bytes = (bits + 7)/8;
     byte[]  buffer = new byte[4096];

     int count = instr.read(buffer) ;
     while(count >= 0) {
        hasher.absorb(buffer,0,count);
        count = instr.read(buffer);
     }

     hasher.absorbStop();
     hasher.absorb( (byte)bytes );
     return hasher.squeeze(bytes);
  }

  public void combine(java.io.InputStream instr,
                      java.io.OutputStream outstr) 
     throws java.io.IOException {
      byte[] buffer = new byte[4096];
 
      int count = instr.read(buffer) ;
      while(count >= 0) {
         squeezeXOR(buffer,0,count);
         outstr.write(buffer,0,count);
         count = instr.read(buffer);
      }
   }

   
  public static void encrypt(String key,
                     java.io.InputStream instr, 
                     java.io.OutputStream outstr) 
    throws java.io.IOException {

     java.util.Random rnd = new java.util.Random(System.currentTimeMillis());
     byte[] iv = new byte[4];
     rnd.nextBytes(iv);

     SpritzCipher cipher = cipherStream(key, iv);

     // first, write the iv..
     outstr.write(iv);

     // now, write 4 random bytes, and a hash of them...
     // so we can tell if we have the right password
     // on decryption
     byte[] randomBytes = new byte[4];
     rnd.nextBytes(randomBytes);
     byte[] hashedBytes = hash(32,randomBytes);
     cipher.squeezeXOR(randomBytes);
     cipher.squeezeXOR(hashedBytes);
     outstr.write(randomBytes);
     outstr.write(hashedBytes);

     // now just write the encrypted stream...
     cipher.combine(instr, outstr);

  }

  private static int readFully(java.io.InputStream instr,
                               byte[] buffer) throws java.io.IOException {

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

  public static void decrypt(String key, 
                             java.io.InputStream instr, 
                             java.io.OutputStream outstr) 
    throws java.io.IOException {
     
     byte[] iv = new byte[4];
     if( readFully(instr, iv) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough to contain an IV!");
     }

     SpritzCipher cipher = cipherStream(key, iv);

     // now verify the random bytes and their hash...
     byte[] randomBytes = new byte[4];
     if( readFully(instr, randomBytes) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough for a header!");
     }
     byte[] randomHash = new byte[4];
     if( readFully(instr, randomHash) != 4 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough for a header!");
     }
     cipher.squeezeXOR(randomBytes);
     cipher.squeezeXOR(randomHash); 
     byte[] testHash = hash(32,randomBytes);
     if( !java.util.Arrays.equals(testHash,randomHash) ) {
         throw new IllegalStateException("Bad Password or corrupted file!");
     } 

     // now decrypt the rest of the bytes, which
     // is the data payload
     cipher.combine(instr, outstr) ;
  }

}

