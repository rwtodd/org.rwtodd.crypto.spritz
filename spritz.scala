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

  /** Abosrb a single byte. */
  def absorb(b: Byte): Unit =  {
     absorbNibble( b & 0x0F )        // low bits
     absorbNibble( (b & 0xFF) >> 4 ) // high bits
  }

  /** Abosrb a sequence of bytes. */
  def absorb(i: Seq[Byte]): Unit = i foreach absorb 

  private def swap(e1: Int, e2: Int) = {
     val tmp = s(e1) ; s(e1) = s(e2) ; s(e2) = tmp
  }

  private def absorbNibble(x: Int) = {
    if (a == 128) { shuffle() }
    swap(a, 128 + x)  // no need for mod here due to nibble size
    a = a + 1
  }

  /** Inserts a separator between absorbed sources. 
    * Use this, for example, between the encryption 
    * key and the initialization vector.
    */ 
  def absorbStop() = {
    if (a == 128) { shuffle() }
    a = a + 1
  } 

  private def shuffle() = {
     whip(512)
     crush()
     whip(512)
     crush()
     whip(512)
     a = 0
  }

  private def GCD(e1: Int, e2: Int): Int = {
    if (e2 == 0) e1 else GCD(e2, e1 % e2)
  }

  private def whip(r: Int) = {
    for(v <- 0 until r) { update() }
    w = (w + 1) & 0xff
    while(GCD(w,256) != 1) { w = (w + 1) & 0xff } 
  } 

  private def crush() = {
     for { v <- 0 until 128 
           if ( (s(v) & 0xff) > (s(256 - 1 - v) & 0xff) ) } {
        swap(v, 256 - 1 - v)
     }
  }

  /** Fill buf with random bytes. This should only
    * be called after one or more calls to absorb. 
    */
  def squeeze(buf: Array[Byte]): Array[Byte] = {
    if (a > 0) { shuffle() }
    for(idx <- 0 until buf.length) {
      buf(idx) = dripOne().toByte
    } 
    buf
  }

  /** Create an array of r random bytes. This should only
    * be called after one or more calls to absorb. 
    */
  def squeeze(r: Int): Array[Byte] = {
    squeeze( new Array[Byte](r) )
  } 
  
  /** Like squeeze, but XORs into the existing buffer.
    * Obviously this is here to encrypt or decrypt 
    * arrays of data.
    */
  def squeezeXOR(buf: Array[Byte]): Array[Byte] = {
    if (a > 0) { shuffle() }
    for(idx <- 0 until buf.length) {
      buf(idx) = (buf(idx) ^ dripOne()).toByte
    } 
    buf
  }

  /** Generate a single random byte. Only to be
    * used after one or more calls to absorb.
    */
  def drip() = {
    if (a > 0) { shuffle() }
    dripOne().toByte
  }

  private def update() = {
     i = (i + w) % 256
     val si = s(i) & 0xff
     val sjsi = s( (j + si) % 256 ) & 0xff
     j = ( k + sjsi ) % 256
     val sj = s(j) & 0xff
     k = ( i + k + sj ) % 256
     swap(i,j)
  }

  private def dripOne(): Int = {
     update()
     val step1 = s( (z + k) % 256 ) & 0xff
     val step2 = s( (i + step1) % 256 ) & 0xff
     z =  s( (j + step2) % 256 ) & 0xff
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

  def hash(bits: Int, data: Seq[Byte]):Array[Byte] = {
     val bytes = (bits + 7)/8
     val pwhash = new SpritzCipher
     pwhash.absorb(data)
     pwhash.absorbStop()
     pwhash.absorb( bytes.toByte )
     pwhash.squeeze(bytes) 
  }
}

