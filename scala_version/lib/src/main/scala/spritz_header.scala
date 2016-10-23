package com.waywardcode.crypto

// This implementation is copyright 2015 Richard Todd
// The license is GPL, see the LICENSE file in the repository.

import java.io.File
import java.io.OutputStream
import java.io.InputStream
import java.util.Random
import java.io.IOException
import java.util.Arrays
import java.nio.charset.StandardCharsets.UTF_8


final class SpritzHeader(val iv : Array[Byte], val payloadKey: Array[Byte]) {

   def write(out : OutputStream, password : String) : Unit = {
        import StreamUtils._

        // first, write the encrypted iv...
        val encIV = Arrays.copyOf(iv, 4);
        xorInto(encIV, SpritzCipher.hash(32, password.getBytes(UTF_8)))
        out.write(encIV)

        val cipher = SpritzCipher.cipherStream(password, Arrays.copyOf(iv,4));

        // now, write 4 random bytes, and a hash of them...
        // so we can tell if we have the right password
        // on decryption
        val rBytes = randomBytes(4)
        val toSkip = rBytes(3) & 0xFF

        val hashedBytes = SpritzCipher.hash(32, rBytes)
        cipher.squeezeXOR(rBytes)
        cipher.skip(toSkip)
        cipher.squeezeXOR(hashedBytes)
        out.write(rBytes)
        out.write(hashedBytes)

        val encKey = Arrays.copyOf(payloadKey, 64)
        cipher.squeezeXOR(encKey)
        out.write(encKey)
   }

}

object SpritzHeader {
   import StreamUtils._

   val size : Int = 64+12

   /** Create random header data */
   def random() = new SpritzHeader(randomBytes(4),randomBytes(64))

   /**
    * Create a new SpritzHeader, keeping the payload key
    * from an existing header, but generating a new IV.
    */
   def changeIV(old : SpritzHeader) = new SpritzHeader(randomBytes(4), old.payloadKey)

   /** Read header data from a stream. */
   def fromStream(in : InputStream, password : String) : SpritzHeader = {
        import StreamUtils._
	
        val iv = new Array[Byte](4);
        if (readFully(in, iv) != 4) {
            throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!");
        }

        xorInto(iv, SpritzCipher.hash(32, password.getBytes(UTF_8)))
        val cipher = SpritzCipher.cipherStream(password,
	                                       Arrays.copyOf(iv,4))

        /* now decrypt the rest of the header */
        val header = new Array[Byte](72)
        if (readFully(in, header) != 72) {
            throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!")
        }
        cipher.squeezeXOR(header, 0, 4)
        cipher.skip(header(3)&0xFF)
        cipher.squeezeXOR(header, 4, 68)

        // now verify the random bytes and their hash...
        val rBytes = Arrays.copyOfRange(header, 0, 4)
        val randomHash = Arrays.copyOfRange(header, 4, 8)
        val testHash = SpritzCipher.hash(32, rBytes)
        if (!java.util.Arrays.equals(testHash, randomHash)) {
            throw new IllegalStateException("Bad Password or corrupted file!")
        }

        val plk = Arrays.copyOfRange(header, 8, 72)
        new SpritzHeader(iv, plk)
   }

}

/**
 * Some utilty methods for classes in this file to use.
 */
private object StreamUtils {
   /**
    * Read enough bytes to fill the buffer, or until the end 
    * of the stream, whichever comes first.
    * @param instr The input stream to use
    * @param buffer The buffer to fill
    * @return the number of bytes read
    */
  def readFully(instr : InputStream, buffer : Array[Byte]) : Int = {
     var total = buffer.length
     var offset = 0
     while (total > 0) {
        val amount = instr.read(buffer, offset, total)
	if (amount >= 0) {
           offset += amount
	   total  -= amount
        } else {
           total = 0
        }
     }
     offset
  }

   /**
     * Utility to XOR two byte arrays.
     * @param dest the destination array
     * @param src  the source array
     */
   def xorInto(dest: Array[Byte], src : Array[Byte]) : Unit = {
      for(idx <- (0 until dest.length)) {
          dest(idx) = (dest(idx) ^ src(idx)).toByte
      }
   }

   /** 
    * Produce random bytes.
    */
   val rnd = new Random(System.currentTimeMillis())
   def randomBytes(n : Int) : Array[Byte] = {
      val ans = new Array[Byte](n)
      rnd.nextBytes(ans)
      ans
   } 
}
