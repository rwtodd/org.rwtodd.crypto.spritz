// A Spritz Cipher driver program to Encrypt/Decrypt files. 

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

package rwt.spritz

import com.waywardcode.crypto.{SpritzCipher, SpritzInputStream, SpritzOutputStream}
import java.io.{FileInputStream,FileOutputStream}
import joptsimple.OptionParser

object Crypt {

  private def copy(instr: java.io.InputStream,
                   outstr: java.io.OutputStream): Unit = {
     val buffer = new Array[Byte](4096)

     var count = instr.read(buffer) 
     while(count >= 0) {
        outstr.write(buffer,0,count)
        count = instr.read(buffer)
     }
  }
 
  private def decryptOne(pw: String)(fname: String): Unit = {
     val outname = if(fname.endsWith(".spritz")) {
                        fname.dropRight(7)
                     } else {
                        fname + ".unenc"
                     }
     val (instream, outstream) = fname match {
          case "-" => (System.in, System.out)
          case _   => (new FileInputStream(fname),
                       new FileOutputStream(outname))
     }
     try {
          copy(new SpritzInputStream(pw, instream), outstream)
          if(outstream != System.out) {
            println(s"$fname -decrypt-> $outname")
          } 
     } catch {
        case e: Exception => println("Error: " + e.toString())
     } finally {
       instream.close()
       outstream.close()
     }
  }

  private def encryptOne(pw: String)(fname: String): Unit = {
     val outname = fname + ".spritz" 
     val (instream, outstream) = fname match {
          case "-" => (System.in, System.out)
          case _   => (new FileInputStream(fname),
                       new FileOutputStream(outname))
     }
     try {
          copy(instream, new SpritzOutputStream(pw, outstream))
          if(outstream != System.out) {
            println(s"$fname -encrypt-> $outname")
          } 
     } catch {
        case e: Exception => println("Error: " + e.toString())
     } finally {
       instream.close()
       outstream.close()
     }
  }

  def cmd(args: Seq[String]): Unit = {
     val jopt = new OptionParser()
     val dOption = jopt.accepts("d")
     val pOption = jopt.accepts("p").
                        withRequiredArg.
                        ofType(classOf[String]).
                        defaultsTo("")
     val files = jopt.nonOptions.ofType(classOf[String])
     jopt.posixlyCorrect(true)

     val opts = jopt.parse(args:_*)
     val passwd = opts.valueOf(pOption)
     if(passwd.length == 0) {
        throw new Exception("Password Required!")
     }

     val process = if(opts.has(dOption)) { encryptOne(passwd)_ } 
                                    else { decryptOne(passwd)_ }

     import scala.collection.JavaConversions._ // to iterate over java List

     var flist = opts.valuesOf(files)
     if(flist.size == 0) { flist = flist ++ Seq("-") }
     flist foreach process
  }

}
