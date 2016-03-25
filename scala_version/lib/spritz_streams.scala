package com.waywardcode.crypto

// This implementation is copyright 2015 Richard Todd
// The license is GPL, see the LICENSE file in the repository.

/** Implements an encrypted output stream via the Spritz stream cipher. 
  * This class uses SpritzCipher for all the heavy lifting.
  * @author Richard Todd
  */
class SpritzOutputStream(key: String, 
                         os: java.io.OutputStream)
 extends java.io.FilterOutputStream(os) {
     private def init : SpritzCipher = {
	     val rnd = new java.util.Random(System.currentTimeMillis)
	     val iv = new Array[Byte](4)
	     rnd.nextBytes(iv)
	     val cipher = SpritzCipher.cipherStream(key,iv) 
	     os.write(iv)
	     val randomBytes = new Array[Byte](4)
	     rnd.nextBytes(randomBytes)
	     val hashedBytes = SpritzCipher.hash(32,randomBytes)
	     cipher.squeezeXOR(randomBytes)
	     cipher.squeezeXOR(hashedBytes)
	     os.write(randomBytes)
	     os.write(hashedBytes)
             cipher
     }

     private val cipher  = init

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
        cipher.squeezeXOR(b.view(off,off+len));
        os.write(b,off,len);
     }
}

/** Implements an encrypted input stream via the Spritz stream cipher. 
  * This class uses SpritzCipher for all the heavy lifting.
  * @author Richard Todd
  */
class SpritzInputStream(key: String, 
                        is: java.io.InputStream) 
   extends java.io.FilterInputStream(is)  {

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
  private def init : SpritzCipher = {
     val initial = new Array[Byte](12)
     if( readFully(initial) != 12 ) {
         throw new IllegalArgumentException("Instream wasn't even long enough to contain an encrypted stream!");
     }
     val cipher = SpritzCipher.cipherStream(key, initial.view(0,4))
     cipher.squeezeXOR(initial.view(4,12))
     val randBytes = initial.view(4,8)
     val randHash  = initial.view(8,12)
     val testHash = SpritzCipher.hash(32,randBytes)
     if (!testHash.sameElements(randHash)) {
         throw new IllegalStateException("Bad Password or corrupted file!");
     } 

     cipher
  }

  private val cipher = init

  private def readFully(buffer : Array[Byte]) : Int = { 
      var total = buffer.length;
      var offset = 0;

      while( total > 0 ) {
         val amount = is.read(buffer, offset, total)
         if (amount >= 0) {
           offset += amount
           total -= amount
         } else {
            total = 0
         }
      } 
      offset
  }


  /** Reads a single byte.
    * @return the decrypted byte.
    */
  override def read() : Int  = {
     is.read() ^ cipher.drip();
  }
 
  /** Reads a series of bytes.
    * @param b the buffer to read into.
    * @param off offset into the buffer.
    * @param the maximum amount of bytes to read.
    * @return the number of bytes read.
    */
  override def read(b: Array[Byte], off: Int, len: Int) : Int = {
    val amt = is.read(b,off,len);
    cipher.squeezeXOR(b.view(off,off+amt))
    amt 
  } 

  /** Skips over some input bytes.
    * @param n the number of bytes to skip.
    * @return the actual number skipped (may be less than n)
    */
  override def skip(n : Long) : Long = {
    val ans = is.skip(n);
    for( _ <- 1L until ans ) { cipher.drip() }
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

