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

package com.waywardcode.crypto


/** Implements the Spritz stream cipher. 
  * This class does the actual calculation, and
  * encapsulates the internal spritz state. 
  * A companion object is provided with
  * helper functions for use in common cases.
  */
class SpritzCipher {
  private var i,j,k,z,a = 0   // these are terrible names,
  private var w = 1           // but match the RS14.pdf description
  private val s = Array.tabulate(256) { _.toByte }

  /** Abosrb a single byte. 
    * @param b the byte to absorb.
    */
  def absorb(b: Byte): Unit =  {
     absorbNibble( b & 0x0F )        // low bits
     absorbNibble( (b & 0xFF) >> 4 ) // high bits
  }

  /** Abosrb a sequence of bytes. 
    * @param bs the bytes to absorb.
    */
  def absorb(bs: Seq[Byte]): Unit = bs foreach absorb 

  private def swap(e1: Int, e2: Int) = {
     val tmp = s(e1) ; s(e1) = s(e2) ; s(e2) = tmp
  }

  private def absorbNibble(x: Int) = {
    if (a == 128) { shuffle() }
    swap(a, 128 + x)  // no need for mod here due to nibble size
    a += 1
  }

  /** Inserts a separator between absorbed sources. 
    * Use this, for example, between the encryption 
    * key and the initialization vector.
    */ 
  def absorbStop() = {
    if (a == 128) { shuffle() }
    a += 1
  } 

  private def shuffle() = {
     whip(512)
     crush()
     whip(512)
     crush()
     whip(512)
     a = 0
  }

  private def whip(r: Int) = {
    def GCD(e1: Int, e2: Int): Int = {
       if (e2 == 0) e1 else GCD(e2, e1 % e2)
    }

    (1 to r) foreach { _ => update() }
    do { 
      w = (w + 1) & 0xff
    } while(GCD(w,256) != 1)
  } 

  private def crush() = {
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
  def squeezeXOR(buf: Array[Byte]): Array[Byte] = {
    if (a > 0) { shuffle() }
    buf transform { item => (item ^ dripOne()).toByte }
    buf
  }

  /** Generate a single random byte. Only to be
    * used after one or more calls to absorb.
    * @return the next byte from the cipher stream
    */
  def drip() = {
    if (a > 0) { shuffle() }
    dripOne().toByte
  }

  private def update() = {
     i = (i + w) & 0xff 
     val si = s(i) & 0xff
     val sjsi = s( (j + si) & 0xff ) & 0xff
     j = ( k + sjsi ) & 0xff 
     val sj = s(j) & 0xff
     k = ( i + k + sj ) & 0xff 
     swap(i,j)
  }

  private def dripOne(): Int = {
     update()
     val step1 = s( (z + k) & 0xff ) & 0xff
     val step2 = s( (i + step1) & 0xff ) & 0xff
     z =  s( (j + step2) & 0xff ) & 0xff
     z
  }

}

// The companion object helps use the cipher
// in common scenarios.
object SpritzCipher {
  def cipherStream(key: String): SpritzCipher = {
     val pwhash = hash(256, key.getBytes("UTF-8")) 
     val encStream = new SpritzCipher
     encStream.absorb(pwhash)
     encStream
  }

  def hash(bits: Int, data: Seq[Byte]): Array[Byte] = {
     val bytes = (bits + 7)/8
     val hasher = new SpritzCipher
     hasher.absorb(data)
     hasher.absorbStop()
     hasher.absorb( bytes.toByte )
     hasher.squeeze(bytes) 
  }

  def hash(bits: Int, instr: java.io.InputStream): Array[Byte] = {
     val hasher = new SpritzCipher
     val bytes = (bits + 7)/8
     val buffer = new Array[Byte](1024)

     var count = instr.read(buffer) 
     while(count >= 0) {
        for( idx <- 0 until count) {
            hasher.absorb( buffer(idx) )
        }
        count = instr.read(buffer)
     }
     hasher.absorbStop()
     hasher.absorb( bytes.toByte )
     hasher.squeeze(bytes)
  }
}

