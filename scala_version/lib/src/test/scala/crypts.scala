package rwt.tests

import org.junit.Test
import org.junit.Assert._
import scala.util.Random
import java.io.{InputStream,InputStreamReader,BufferedReader}
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets.UTF_8

import com.waywardcode.crypto.SpritzCipher
import com.waywardcode.crypto.SpritzInputStream
import com.waywardcode.crypto.SpritzOutputStream

class CryptTests {
  def bytes(xs: Int*) :Array[Byte] = xs.map(_.toByte).toArray

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

  @Test def canReadOwnOutput() : Unit = {
      // encrypt random stuff 20 times...
      for( idx <- 1 to 20 ) {
         // random password
         val passwd = Random.alphanumeric.take(12).mkString
               
         // random original name 
         val origname  = if(Random.nextBoolean())  Some(Random.alphanumeric.take(12).mkString)
                         else None

         // random length of content
         val contentLength = Random.nextInt(4096) + 1

         // random content
         val content = new Array[Byte](contentLength)
         Random.nextBytes(content)

         // encrypt...
         val outbytes = new ByteArrayOutputStream()
         val ostr = new SpritzOutputStream(origname, passwd, outbytes)
         ostr.outputStream.write(content)
         ostr.close()

         // decrypt...
         val outbuf = new Array[Byte](4096)
         val inbytes = new ByteArrayInputStream( outbytes.toByteArray() )
         val istr = new SpritzInputStream(passwd, inbytes )
         val sz = readFully(istr.inputStream,outbuf)
         assertEquals(s"Content length, test#$idx", contentLength, sz)
         istr.close()         
         assertArrayEquals(s"Content, test#$idx", 
                           content, 
                           outbuf.take(sz))
      }
  }

  @Test def canReadKnownGoodFile() : Unit = {
      val tfile = bytes( 
         0x21, 0x01, 0x9b, 0x59, 0xaa, 0x4f, 0x76, 0x12,
         0xa2, 0x6a, 0xd4, 0x8b, 0x8d, 0x3f, 0xc2, 0xb9,
         0xeb, 0xa5, 0x31, 0x8f, 0xd8, 0xe1, 0x01, 0x6b,
         0xc7, 0x1a, 0x1c, 0x5f, 0xab, 0xf9, 0xf6, 0xab,
         0x6d, 0x81, 0x1b, 0x14, 0x04, 0x6b, 0x62, 0x6f,
         0xce, 0xaa, 0x2a, 0xb7, 0xb4, 0xd8, 0xed, 0xbf,
         0x49, 0x7c, 0xd0, 0x00, 0xa2, 0x91, 0x30, 0x91,
         0xda, 0x7f, 0x3e, 0xd2, 0xd4, 0xda, 0x56, 0xf4,
         0x50, 0x21, 0x63, 0x99, 0x4c, 0x58, 0x54, 0xb9,
         0xee, 0x1a, 0xf4, 0x5e, 0x6e, 0xcc, 0x63, 0xd1,
         0xab, 0xc4, 0xb3, 0xf3, 0x2a, 0x7e, 0xbd, 0x5d,
         0x6e, 0x9a, 0xcb, 0xba, 0xd9, 0x47, 0x7e, 0xa4,
         0x23, 0x18, 0xb4, 0xfc, 0x8d, 0x01, 0x27, 0x7d,
         0x00, 0x00, 0xd8, 0x37, 0x7b
      ) 
      val inbytes = new ByteArrayInputStream(tfile)
      val istr = new SpritzInputStream("1234", inbytes)
      var inrdr = new BufferedReader(new InputStreamReader(istr.inputStream, UTF_8))
      
      // now see if the output is good...
      assertEquals("1st line", "abc", inrdr.readLine()) 
      assertEquals("2nd line", "abc", inrdr.readLine()) 
      assertEquals("3rd line", "123", inrdr.readLine()) 
      assertEquals("4th line", "123", inrdr.readLine()) 
      assertEquals("last line", "", inrdr.readLine()) 
      assertEquals("end of file", null, inrdr.readLine()) 
      inrdr.close()
      istr.close()
  }

}
