// The Spritz Cipher
// This implementation is copyright 2015 Richard Todd
// The license is GPL, see the LICENSE file in the repository.

package com.waywardcode.crypto

import java.nio.charset.StandardCharsets.UTF_8

/** Implements the Spritz stream cipher. 
  * This class does the actual calculation, and
  * encapsulates the internal spritz state. 
  * A companion object is provided with
  * helper functions for use in common cases.
  * @author Richard Todd
  */
final class SpritzCipher {
  private var i,j,k,z,a = 0   // these are terrible names,
  private var w = 1           // but match the RS14.pdf description
  private val s = Array.tabulate(256) { _.toByte }

  private def reset() : Unit = {
     i = 0 ; j = 0 ; k = 0
     z = 0 ; a = 0 ; w = 1
     for( idx <- (0 to 255) ) {
        s(idx) = idx.toByte
     }
  }

  /** Abosrb a single byte. 
    * @param b the byte to absorb.
    */
  def absorb(b: Byte): Unit =  {
     absorbNibble( b & 0x0F )        // low bits
     absorbNibble( (b & 0xFF) >> 4 ) // high bits
  }

  /** Abosrb a sequence of bytes. 
    * @param bs the bytes to absorb.
    * @param start the first byte to absorb (inclusive)
    * @param end   the last index to absorb (exclusive)
    */
  def absorb(bs: Array[Byte], start : Int, end : Int): Unit = {
       for( idx <- (start until end) ) {
          absorb(bs(idx))
       }
  }

  /** Abosrb a sequence of bytes. 
    * @param bs the bytes to absorb.
    */
  @inline
  def absorb(bs: Array[Byte]) : Unit = absorb(bs, 0, bs.length)

  @inline
  private def swap(e1: Int, e2: Int) : Unit = {
     val tmp = s(e1) ; s(e1) = s(e2) ; s(e2) = tmp
  }

  private def absorbNibble(x: Int) : Unit = {
    if (a == 128) { shuffle() }
    swap(a, 128 + x)  // no need for mod here due to nibble size
    a += 1
  }

  /**
     * convert an integer into a big-endian array of component bytes, absorbing
     * it into the spritz sponge. It would take an obscenely-large hash to need
     * more than 2 bytes, so this recursive implementation should be ok. It's
     * the cleanest-looking version of the algorithm I could derive, without
     * building a stack-like collection of bytes.
     *
     * @param n The value to split into bytes
     */
  def  absorbIntBytes(n : Int) : Unit = {
     if (n > 255) {
        absorbIntBytes(n >> 8);
     }
     absorb(n.toByte);
  }


  /** Inserts a separator between absorbed sources. 
    * Use this, for example, between the encryption 
    * key and the initialization vector.
    */ 
  def absorbStop() : Unit = {
    if (a == 128) { shuffle() }
    a += 1
  } 

  private def shuffle(): Unit = {
     whip() ; crush()
     whip() ; crush()
     whip()
     a = 0
  }

  private def whip() : Unit = {
    update(512)
    w = (w + 2) & 0xff
  } 

  private def crush() : Unit = {
     for { v <- 0 until 128 
           if ( (s(v) & 0xff) > (s(256 - 1 - v) & 0xff) ) } {
        swap(v, 256 - 1 - v)
     }
  }

  /** Fill buf with cipher bytes. This should only
    * be called after one or more calls to absorb. 
    * @param buf the array to overwrite with the cipher stream.
    * @return the transformed array
    */
  def squeeze(buf: Array[Byte]): Array[Byte] = {
    if (a > 0) { shuffle() }
    buf transform { _ => dripOne().toByte }
    buf
  }

  /** Skip a number of cipher stream bytes.
    * @param amt the number of bytes to skip.
    */
  def skip(amt: Long) : Unit = {
    if (a > 0) { shuffle() }
    for( idx <- (0L until amt) ) {
       dripOne()
    }
  }
  
  /** Create an array of cipher bytes. This should only
    * be called after one or more calls to absorb. 
    * @param count the number of bytes to squeeze 
    * @return a newly-created array of bytes from the cipher
    */
  def squeeze(count: Int): Array[Byte] = {
    squeeze( new Array[Byte](count) )
  } 
  
  /** Like squeeze, but XORs into the existing buffer.
    * Obviously this is here to encrypt or decrypt 
    * arrays of data.
    * @param buf a buffer of data to encrypt/decrypt 
    *   against the cipher stream.
    * @return the transformed array
    */
  def squeezeXOR(buf: Array[Byte], offs: Int, len: Int) : Array[Byte] = {
    if (a > 0) { shuffle() }
    for( idx <- (offs until (offs+len)) ) {
        buf(idx) = (buf(idx) ^ dripOne()).toByte
    }
    buf
  }

  @inline
  def squeezeXOR(buf: Array[Byte]) : Array[Byte] = 
     squeezeXOR(buf, 0, buf.length)


  /** Generate a single random byte. Only to be
    * used after one or more calls to absorb.
    * @return the next byte from the cipher stream
    */
  def drip() : Byte = {
    if (a > 0) { shuffle() }
    dripOne().toByte
  }

  private def update(times: Int = 1) : Unit = {
     var mi = i
     var mj = j
     var mk = k
     val mw = w

     var mtimes = times     
     while(mtimes > 0) { 
         mi = (mi + mw) & 0xff 
         val smi = s(mi) & 0xff
         val sjsi = s( (mj + smi) & 0xff ) & 0xff
         mj = ( mk + sjsi ) & 0xff 
         val smj = s(mj) & 0xff
         mk = ( mi + mk + smj ) & 0xff 
         s(mi) = smj.toByte
         s(mj) = smi.toByte
         mtimes = mtimes - 1
     }

     i = mi
     j = mj
     k = mk 
  }

  private def dripOne(): Int = {
     update()
     val step1 = s( (z + k) & 0xff ) & 0xff
     val step2 = s( (i + step1) & 0xff ) & 0xff
     z =  s( (j + step2) & 0xff ) & 0xff
     z
  }

}


/** Convenience functions for common uses of SpritzCipher.
  * @author Richard Todd
  */
object SpritzCipher {
  def cipherStream(key: String, iv: Array[Byte]): SpritzCipher = {
     require(iv.length == 4) // must have a 32-bit iv these days
     
     val keyBytes = hash(512, key.getBytes(UTF_8))    
     val initSpritz = new SpritzCipher
     val iterations = 20000 + (iv(3) & 0xFF)     
     
     (1 to iterations) foreach { _ =>
         initSpritz.reset()
	 initSpritz.absorb(iv)
	 initSpritz.absorbStop()
	 initSpritz.absorb(keyBytes)
	 initSpritz.squeeze(keyBytes)
	 iv(0) = ((iv(0) & 0xFF) + 1).toByte
	 if (iv(0) == 0) {
           iv(1) = ((iv(1) & 0xFF) + 1).toByte
           if (iv(1) == 0) {
              iv(2) = ((iv(2) & 0xFF) + 1).toByte
              if (iv(2) == 0) {
                 iv(3) = ((iv(3) & 0xFF) + 1).toByte
              }
           }
         }
     }

     initSpritz.reset()
     initSpritz.absorb(keyBytes)
     initSpritz
  }

    /**
     * Hash an array of bytes. Can create a hash of as many bits as required,
     * rounded up to a byte boundary.
     *
     * @param bits how many bits wide to make the hash.
     * @param data the data to hash.
     * @return the hash
     */
  def hash(bits: Int, data: Array[Byte]): Array[Byte] = {
     val bytes = (bits + 7)/8
     val hasher = new SpritzCipher
     hasher.absorb(data)
     hasher.absorbStop()
     hasher.absorbIntBytes(bytes)
     hasher.squeeze(bytes) 
  }

    /**
     * Hash an input stream. Can create a hash of as many bits as required,
     * rounded up to a byte boundary. Note that the method reads until no more
     * data is available, but it doesn't close the stream.
     *
     * @param bits how many bits wide to make the hash.
     * @param instr the data to hash.
     * @return the hash
     * @throws java.io.IOException if there is a problem with the IO
     */
  def hash(bits: Int, instr: java.io.InputStream): Array[Byte] = {
     val hasher = new SpritzCipher
     val bytes = (bits + 7)/8
     val buffer = new Array[Byte](4096)

     var count = instr.read(buffer) 
     while(count >= 0) {
        hasher.absorb(buffer, 0, count)
        count = instr.read(buffer)
     }

     hasher.absorbStop()
     hasher.absorbIntBytes(bytes)
     hasher.squeeze(bytes)
  }
}

