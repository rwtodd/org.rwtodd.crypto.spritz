// A Spritz Cipher driver program to hash files. 

// This implementation is copyright 2015 Richard Todd
// The license is GPL, see the LICENSE file in the repository.

package rwt.spritz

import com.waywardcode.crypto.SpritzCipher
import java.io.FileInputStream

object Hash {
 
  private def doOne(size: Int)(fname: String): String = {
     val fstream = fname match {
        case "-" => System.in
        case _   => new FileInputStream(fname)
     }
     val answer = SpritzCipher.hash(size, fstream) 
     fstream.close()

     val sb = new scala.collection.mutable.StringBuilder(fname).append(": ")
     answer.foreach( b => sb.append("%02x".format(b)) )
     sb.toString()
  }

  def cmd(args: List[String]): Unit = {

     var size = 256

     @annotation.tailrec
     def parseArgs(args: List[String]) : List[String] = {
        args match {
          case "-s" :: sz :: rest => size = sz.toInt
                                     parseArgs(rest)
          case rest               => rest
        }
     }

     var flist = parseArgs(args)
     if(flist.isEmpty) { flist = List("-") }
     flist.par.map(doOne(size)).foreach(println)
  }

}
