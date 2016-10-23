package rwt.tests

import org.junit.Test
import org.junit.Assert._
import java.nio.charset.StandardCharsets.UTF_8

import com.waywardcode.crypto.SpritzCipher

class HashTests {
  def bytes(xs: Int*) :Array[Byte] = xs.map(_.toByte).toArray

  @Test def officialTestHashes() : Unit = {
      val tests = Map(
         "ABC" -> bytes(0x02, 0x8f, 0xa2, 0xb4, 0x8b, 0x93, 0x4a, 0x18),
         "spam" -> bytes(0xac, 0xbb, 0xa0, 0x81, 0x3f, 0x30, 0x0d, 0x3a),
         "arcfour" -> bytes(0xff, 0x8c, 0xf2, 0x68, 0x09, 0x4c, 0x87, 0xb9))

      for( (k,v) <- tests ) {
         assertArrayEquals(s"Hash of $k", 
                           v, 
                           SpritzCipher.hash(256, k.getBytes(UTF_8)).take(8))
      }
  }

}
