package rwt.spritz

import java.io._
import com.waywardcode.crypto._

object RePass {
    def repass(f : File, oldkey : String, newkey : String): String = {
        val headerBytes = new Array[Byte](SpritzHeader.size);
        
        val raf = new RandomAccessFile(f, "rw")
        try { 
            raf.seek(0)
            raf.readFully(headerBytes)
            val is = new ByteArrayInputStream(headerBytes) 
            val oldHdr = SpritzHeader.fromStream(is, oldkey) 
            val os = new ByteArrayOutputStream()
            SpritzHeader.changeIV(oldHdr).write(os, newkey)
            raf.seek(0)
            raf.write(os.toByteArray)  
        } catch {
            case e : Exception => return e.toString();
        } finally {
            raf.close()
        }

        f.getName()
    }
    
    def cmd(args: List[String]) : Unit = {
      var oldPw : String = ""
      var newPw : String = "" 

      @annotation.tailrec
      def parseArgs(args: List[String]) : List[String] = {
        args match {
          case "-op" :: pw :: rest => oldPw = pw
	                              parseArgs(rest)
          case "-np" :: pw :: rest => newPw = pw
                                      parseArgs(rest)
          case rest                => rest
        }
      }

     var flist = parseArgs(args)
     if (oldPw.length == 0) {
        oldPw = Passwords.getPassword("Old Password: ", false).getOrElse("")
         
        if (oldPw.length == 0) {
           throw new Exception("Password Required!")
        }
     }

     if (newPw.length == 0) {
        newPw = Passwords.getPassword("New Password: ", true).getOrElse("")
         
        if (newPw.length == 0) {
           throw new Exception("Password Required!")
        }
     }

     flist.par.map(str => repass(new File(str),oldPw,newPw)).foreach(println)
  }
    
}    
