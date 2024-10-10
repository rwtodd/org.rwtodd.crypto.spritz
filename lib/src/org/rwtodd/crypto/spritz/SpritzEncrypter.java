package org.rwtodd.crypto.spritz;


import java.io.File;
import java.io.OutputStream;
import java.io.IOException;
import java.io.FilterOutputStream;
import java.util.Optional;

/** Implements an encrypted output stream via the Spritz stream cipher. 
  * This class uses SpritzCipher for all the heavy lifting.
  * @author Richard Todd
  */
public class SpritzEncrypter extends FilterOutputStream  {
  private final SpritzCipher cipher;

   /** Constructs an encrypted stream, consisting of 
   * a header defined by SpritzHeader, and builds a
   * cipher stream from the header's payload key.
   * @param key the password to use. It is converted to UTF-8 bytes.
   * @param out the next OutputStream in the chain.
   * @throws java.io.IOException if there is a problem writing to 'out'
   */
  public SpritzEncrypter(final String key, final OutputStream out) 
    throws IOException
  {
     super(out);
     SpritzHeader header = new SpritzHeader();
     header.Write(out, key);
     final byte[] payloadKey = header.getPayloadKey();
     
     cipher = new SpritzCipher();
     cipher.absorb(payloadKey);
     cipher.skip(2048 + (payloadKey[3] & 0xFF));     
     
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
    * @throws IOException when there's a problem with the write.
    */
  @Override
  public void write(byte[] b, int off, int len) 
    throws IOException {
     cipher.squeezeXOR(b,off,len);
     out.write(b,off,len);
  }
  
}

