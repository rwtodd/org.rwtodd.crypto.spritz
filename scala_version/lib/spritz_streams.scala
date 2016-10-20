package com.waywardcode.crypto

// This implementation is copyright 2015 Richard Todd
// The license is GPL, see the LICENSE file in the repository.

import java.io.File
import java.io.OutputStream
import java.io.InputStream
import java.io.IOException
import java.util.Arrays
import java.nio.charset.StandardCharsets.UTF_8
import java.util.zip.InflaterInputStream;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Deflater;


/** Implements an encrypted output stream via the Spritz stream cipher. 
  * This class uses SpritzCipher for all the heavy lifting.
  * @author Richard Todd
  */
class SpritzEncrypter(fname: Option[String],
                         key: String, 
                         os: java.io.OutputStream)
 extends java.io.FilterOutputStream(os) {
     private val header = SpritzHeader.random
     header.write(os, key)
     private val cipher = new SpritzCipher
     cipher.absorb(header.payloadKey)
     cipher.skip(2048 + (header.payloadKey(3)&0xFF))
     
     /** write a single byte, encrypted, to the output stream.
       * @param b the byte to write.
       */
     override def write(b: Int) : Unit = os.write( b ^ cipher.drip() )

    /** Write a buffer of encrypted bytes.
      * @param b the bytes to write.
      * @param off where to start in the buffer.
      * @param len how much to write.
      */
     override def write(b: Array[Byte], off: Int, len: Int) : Unit = {
        cipher.squeezeXOR(b,off,len);
        os.write(b,off,len);
     }
}

/** Implements an encrypted input stream via the Spritz stream cipher. 
  * This class uses SpritzCipher for all the heavy lifting.
  * @author Richard Todd
  */
class SpritzDecrypter(key: String, 
                      is: java.io.InputStream) 
   extends java.io.FilterInputStream(is)  {
   
   private val cipher = new SpritzCipher
   private val header = SpritzHeader.fromStream(is, key)
   
   cipher.absorb(header.payloadKey)
   cipher.skip(2048 + (header.payloadKey(3)&0xFF))
   

  /** Reads a single byte.
    * @return the decrypted byte.
    */
  override def read() : Int  = {
     is.read() ^ cipher.drip()
  }
 
  /** Reads a series of bytes.
    * @param b the buffer to read into.
    * @param off offset into the buffer.
    * @param the maximum amount of bytes to read.
    * @return the number of bytes read.
    */
  override def read(b: Array[Byte], off: Int, len: Int) : Int = {
    val amt = is.read(b,off,len);
    cipher.squeezeXOR(b,off,len)
    amt 
  } 

  /** Skips over some input bytes.
    * @param n the number of bytes to skip.
    * @return the actual number skipped (may be less than n)
    */
  override def skip(n : Long) : Long = {
    val ans = is.skip(n)
    cipher.skip(ans)
    ans
  }


  /** Throws an exception since we don't support mark/reset.
    */
  override def reset() : Unit = {
    throw new java.io.IOException("mark/reset not supported on SpritzInputStreams!")
  }

  /** Returns false since we don't support mark/reset. 
    * @return false.
    */
  override def markSupported : Boolean = false

}



/**
 * This is the main class used to read an encrypted stream. It
 * understands the header format, the embedded filename, and
 * the zlib compression.  If you don't want compression, use
 * a SpritzDecrypter directly.  If you don't even want a header,
 * get a SpritzCipher.cipherStream().
 * @author richard
 */
class SpritzInputStream(key: String, is: InputStream)
     extends AutoCloseable {

   import StreamUtils.readFully

   private val decrypter = new SpritzDecrypter(key, is)
   
    /**
     * The original, pre-encryption filename, if it was
     * stored in the encrypted file.
     * @return The original filename.
     */
    val originalName : Option[String] =  (decrypter.read() & 0xFF) match {
         case -1 => 
            throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!")
	 case 0   =>
	    None
	 case len =>  
            val fnameBytes = new Array[Byte](len)
            if (readFully(decrypter, fnameBytes) != len) {
                throw new IllegalStateException("Instream corrupted!")
            }
            Some(new String(fnameBytes, UTF_8))
    }

    /**
     * Gets an InputStream for decompressed, decrypted data.
     * @return An InputStream which can be used to read decrypted bytes 
     */
    val inputStream : InputStream = new InflaterInputStream(decrypter)
    
    override def close() : Unit = {
        inputStream.close()
        decrypter.close()
    }    
}

 /**
 * This is the main class used to write an encrypted stream. It
 * understands the header format, the embedded filename, and
 * the zlib compression.  If you don't want compression, use
 * a SpritzEncrypter directly.  If you don't even want a header,
 * get a SpritzCipher.cipherStream().
 * @author richard
 */
class SpritzOutputStream(val originalName: Option[String],
                         key: String,
                         out: OutputStream)
   extends AutoCloseable {

   private val encrypter = new SpritzEncrypter(originalName, key, out)

   private val nameBytes = originalName.
                           map(new File(_).getName).
			   getOrElse("").
			   getBytes(UTF_8)
   encrypter.write(nameBytes.length)
   encrypter.write(nameBytes)
   
   val outputStream =
       new DeflaterOutputStream(encrypter,
                                new Deflater(Deflater.BEST_COMPRESSION)) 


   override def close() : Unit = {
       outputStream.finish()
       outputStream.close()
       encrypter.close()
   }
}
