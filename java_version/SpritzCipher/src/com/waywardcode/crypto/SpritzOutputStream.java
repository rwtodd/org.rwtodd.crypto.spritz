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


import java.io.File;
import java.io.OutputStream;
import java.io.IOException;
import java.io.FilterOutputStream;
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
    * @throws java.io.IOException
    */
  public SpritzOutputStream(final Optional<String> fname, final String key, final OutputStream out) 
    throws IOException
  {
     super(out);
     final java.util.Random rnd = new java.util.Random(System.currentTimeMillis());
     final byte[] iv = new byte[4];
     rnd.nextBytes(iv);

     cipher = SpritzCipher.cipherStream(key, iv);

     // first, write the version, and iv..
     out.write(1);
     out.write(iv);

     // now, write 4 random bytes, and a hash of them...
     // so we can tell if we have the right password
     // on decryption
     final byte[] randomBytes = new byte[4];
     rnd.nextBytes(randomBytes);
     final byte[] hashedBytes = SpritzCipher.hash(32,randomBytes);
     cipher.squeezeXOR(randomBytes);
     cipher.squeezeXOR(hashedBytes);
     out.write(randomBytes);
     out.write(hashedBytes);
     
     byte[] nameBytes = fname.map( n -> new File(n).getName() ).
                              orElse("").
                              getBytes("UTF-8");
     int nameLen = nameBytes.length ^ cipher.drip();
     cipher.squeezeXOR(nameBytes);
     out.write(nameLen);
     out.write(nameBytes);
  }

  /** Write a single encrypted byte.
    * @param b the byte to write.
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

