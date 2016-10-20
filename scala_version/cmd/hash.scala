// A Spritz Cipher driver program to hash files. 

// This implementation is copyright 2015 Richard Todd
// The license is GPL, see the LICENSE file in the repository.

package rwt.spritz

import com.waywardcode.crypto.SpritzCipher
import java.io.FileInputStream

object Hash {
 
  private def doOne(size: Int, encoder: (Array[Byte]) => String)
                   (fname: String): String = {
     val fstream = fname match {
        case "-" => System.in
        case _   => new FileInputStream(fname)
     }
     val answer = SpritzCipher.hash(size, fstream) 
     fstream.close()

     s"${fname}: ${encoder(answer)}"
  }

  def formatHex(value : Array[Byte]) : String = {
     val sb = new scala.collection.mutable.StringBuilder()
     value foreach { b => sb.append("%02x".format(b)) }
     sb.toString()
  }
  
  def formatBase64(value : Array[Byte]) : String = 
     java.util.Base64.getEncoder.encodeToString(value) 
  

  def cmd(args: List[String]): Unit = {

     var size = 256
     var encoder = formatBase64 _
     
     @annotation.tailrec
     def parseArgs(args: List[String]) : List[String] = {
        args match {
          case "-h" :: rest       => encoder = formatHex _
	                             parseArgs(rest)
          case "-s" :: sz :: rest => size = sz.toInt
                                     parseArgs(rest)
          case rest               => rest
        }
     }

     var flist = parseArgs(args)
     if(flist.isEmpty) { flist = List("-") }
     flist.par.map(doOne(size,encoder)).foreach(println)
  }

}
