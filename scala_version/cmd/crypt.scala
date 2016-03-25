// A Spritz Cipher driver program to Encrypt/Decrypt files. 

// This implementation is copyright 2015 Richard Todd
// The license in GPL, see license file in the repository.

package rwt.spritz

import com.waywardcode.crypto.{SpritzCipher, SpritzInputStream, SpritzOutputStream}
import java.io.{FileInputStream,FileOutputStream}

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
 
  private def changeDir(infl: String, odir: String): String = odir match {
       case ""  =>  infl 
       case _   =>  new java.io.File(odir, new java.io.File(infl).getName).toString 
  }

  private def decryptOne(pw: String, odir: String)(fname: String): Unit = {
     val outname = changeDir(if(fname.endsWith(".spritz")) {
                               fname.dropRight(7)
                             } else {
                               fname + ".unenc"
                             }, odir)
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
     } finally {
       instream.close()
       outstream.close()
     }
  }

  private def encryptOne(pw: String, odir: String)(fname: String): Unit = {
     val outname = changeDir(fname + ".spritz", odir)
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
     } finally {
       instream.close()
       outstream.close()
     }
  }

  private def getPasswd(times: Int): Option[String] = {
     val c = System.console()
     if (c == null) { return None }

     val chrs = c.readPassword("[Password]:")
     for(_ <- 1 until times) {
         val rpt = c.readPassword("[Confirm Password]:")
         if(!rpt.sameElements(chrs)) { throw new Exception("Passwords don't match!") }
     }
     Some(new String(chrs))
  }

  def cmd(args: List[String]): Unit = {
     var decrypt = false
     var passwd = ""
     var odir = ""

     @annotation.tailrec
     def parseArgs(args: List[String]): List[String] = {
        args match {
          case "-d" :: rest        => decrypt = true
                                      parseArgs(rest)
          case "-p" :: str :: rest => passwd  = str
                                      parseArgs(rest)
          case "-o" :: str :: rest => odir = str
                                      parseArgs(rest)
          case rest                => rest
        }
     }
     var flist = parseArgs(args)

     if(passwd.length == 0) {
        passwd = getPasswd(if(decrypt) 1 else 2).getOrElse("")
         
        if(passwd.length == 0) {
           throw new Exception("Password Required!")
        }
     }

     val process = if(decrypt) { decryptOne(passwd,odir)_ } 
                          else { encryptOne(passwd,odir)_ }

     if(flist.isEmpty) { flist = List("-") }
     flist foreach process
  }

}
