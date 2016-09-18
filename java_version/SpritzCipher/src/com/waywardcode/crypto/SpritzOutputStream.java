/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;


import java.io.File;
import java.io.OutputStream;
import java.io.IOException;
import java.io.FilterOutputStream;
import java.util.Arrays;
import java.util.Optional;

/** Implements an encrypted output stream via the Spritz stream cipher. 
  * This class uses SpritzCipher for all the heavy lifting.
  * @author Richard Todd
  */
public class SpritzOutputStream extends FilterOutputStream  {
  private final SpritzCipher cipher;

  /** Constructs an encrypted stream.
    * This method creates a 4-byte random initialization
    * vector, and writes that to the output unencrypted.
    * It then encrypts 4 random bytes, and the 32-bit hash
    * of those bytes.  This way, upon decryption, we can
    * tell immediately if we are using the correct password
    * (since it would be highly unlikely to get the correct
    * hash if we had the wrong spritz stream). 
    * @param fname the filename associated with the unencrypted output
    * @param key the password to use. It is converted to UTF-8 bytes.
    * @param out the next OutputStream in the chain.
    * @throws java.io.IOException if there is a problem writing to 'out'
    */
  public SpritzOutputStream(final Optional<String> fname, final String key, final OutputStream out) 
    throws IOException
  {
     super(out);
     final java.util.Random rnd = new java.util.Random(System.currentTimeMillis());
     final byte[] iv = new byte[4];
     rnd.nextBytes(iv);

     // first, write the encrypted iv...
     final byte[] encIV = Arrays.copyOf(iv, 4);
     SpritzCipher.XORInto(encIV,  SpritzCipher.hash(32, key.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
     out.write(encIV);

     cipher = SpritzCipher.cipherStream(key, iv);

     // now, write 4 random bytes, and a hash of them...
     // so we can tell if we have the right password
     // on decryption
     final byte[] randomBytes = new byte[4];
     rnd.nextBytes(randomBytes);
     final int toSkip = randomBytes[3] & 0xFF;
     
     final byte[] hashedBytes = SpritzCipher.hash(32,randomBytes);
     cipher.squeezeXOR(randomBytes);
     for(int i = 0; i < toSkip; i++) { cipher.drip(); }     
     cipher.squeezeXOR(hashedBytes);
     out.write(randomBytes);
     out.write(hashedBytes);
     
     final byte[] realKey = new byte[64];
     rnd.nextBytes(realKey);
     final byte[] encKey = Arrays.copyOf(realKey, 64);
     cipher.squeezeXOR(encKey);
     out.write(encKey);
     
     cipher.reset();
     cipher.absorb(realKey);
     for(int i = 0; i < (2048 + (realKey[3] & 0xFF)); i++) { cipher.drip(); }     
     
     byte[] nameBytes = fname.map( n -> new File(n).getName() ).
                              orElse("").
                              getBytes("UTF-8");
     int nameLen = nameBytes.length ^ (cipher.drip() & 0xFF);
     cipher.squeezeXOR(nameBytes);
     out.write(nameLen);
     out.write(nameBytes);
  }

  /** Write a single encrypted byte.
    * @param b the byte to write.
    * @throws java.io.IOException if there is a problem writing to the underlying stream
    */
  @Override
  public void write(int b) throws IOException {
     out.write( b ^ cipher.drip() );
  }


  /** Write a buffer of encrypted bytes.
    * @param b the bytes to write.
    * @param off where to start in the buffer.
    * @param len how much to write.
    */
  @Override
  public void write(byte[] b, int off, int len) 
    throws IOException {
     cipher.squeezeXOR(b,off,len);
     out.write(b,off,len);
  }
  
}

