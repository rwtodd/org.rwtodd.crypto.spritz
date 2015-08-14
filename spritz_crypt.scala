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

import com.waywardcode.crypto.SpritzCipher
import java.io.FileInputStream
import java.io.FileOutputStream

object Crypt {
 
  private def doOne(pw: String, fname: String): Unit = {
     val encrypted = """^(.*)\.spritz$""".r
     val outname = fname match {  
          case encrypted(name) => name 
          case _               => s"${fname}.spritz"
     }
     val decrypting = fname.endsWith(".spritz")
 
     val instream = new FileInputStream(fname)
     val outstream = new FileOutputStream( outname )
     try {
       if (decrypting) {
          SpritzCipher.decrypt(pw,instream,outstream)
       } else {
          SpritzCipher.encrypt(pw,instream,outstream)
       }
     } catch {
        case e: Exception => println("Error: " + e.toString())
     } finally {
       instream.close()
       outstream.close()
     }
  }

  def main(args: Array[String]): Unit = {
     val pw = args(0)
     args.iterator.drop(1) foreach { doOne(pw,_) }

  }

}
