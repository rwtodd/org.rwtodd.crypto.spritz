// A Spritz Cipher driver program to Encrypt/Decrypt files. 

// This implementation is copyright 2015 Richard Todd
// The license in GPL, see license file in the repository.

package rwt.spritz

import com.waywardcode.crypto.{SpritzCipher, SpritzInputStream, SpritzOutputStream}
import java.io.{File,FileInputStream,FileOutputStream}

object Crypt {

  /** uses read()/write() to copy one iostream to another.
    */
  private def copy(instr: java.io.InputStream,
                   outstr: java.io.OutputStream): Unit = {
     val buffer = new Array[Byte](4096)

     var count = instr.read(buffer) 
     while(count >= 0) {
        outstr.write(buffer,0,count)
        count = instr.read(buffer)
     }
  }

  /** changes the path of a file, preserving the name */
  private def changeDir(infl: String, odir: String): String = odir match {
       case ""  =>  infl 
       case _   =>  new File(odir, new File(infl).getName).toString 
  }

  /** checks a file to make sure it can be decrypted with the given
    * password.
    */
  private def checkOne(pw: String)(fname: String): String = {
       val instream = fname match {
          case "-" => System.in
          case _   => new FileInputStream(fname)
       }
       try {
          val insideName = new SpritzInputStream(pw, instream).
                                       originalName.
                                       getOrElse("(no name)")
          s"$fname: correct password! File inside is $insideName"
       } catch {
          case e: IllegalStateException => s"$fname: $e"
       }finally {
          instream.close()
       }
  }

  private def decryptOne(pw: String, odir: Option[String])(fname: String): String = {
     val instream = if( fname == "-" ) System.in else new FileInputStream(fname)
     val cipher = new SpritzInputStream(pw, instream)

     val outname = cipher.originalName.getOrElse {
          if(fname.endsWith(".spritz")) fname.dropRight(7)
          else  (fname + ".unenc")
     }
     val outstream = if( fname == "-" ) System.out
                     else {
                           var outdir = odir.getOrElse( new File(fname).getParent )
                           if( outdir == null ) outdir = ""
                           new FileOutputStream(changeDir(outname,outdir))
                     }
     try {
          copy(cipher.inputStream, outstream)
          s"$fname -decrypt-> $outname"
     } finally {
       instream.close()
       outstream.close()
     }
  }

  private def encryptOne(pw: String, odir: Option[String])(fname: String): String = {
     val outname = changeDir(fname + ".dat", odir.getOrElse(""))
     val (instream, outstream, origName) = fname match {
          case "-" => (System.in, System.out, None)
          case _   => (new FileInputStream(fname),
                       new FileOutputStream(outname),
                       Some(fname))
     }
     val encOut = new SpritzOutputStream(origName, pw, outstream)
     try {
          copy(instream, encOut.outputStream)
          s"$fname -encrypt-> $outname"
     } finally {
       instream.close()
       encOut.close()
     }
  }

  def cmd(args: List[String]): Unit = {
     var decrypt = false
     var check   = false   // check supersedes decrypt, if given
     var passwd = ""
     var odir: Option[String] = None

     @annotation.tailrec
     def parseArgs(args: List[String]): List[String] = {
        args match {
          case "-c" :: rest        => check   = true
                                      parseArgs(rest)
          case "-d" :: rest        => decrypt = true
                                      parseArgs(rest)
          case "-p" :: str :: rest => passwd  = str
                                      parseArgs(rest)
          case "-o" :: str :: rest => odir = Some(str)
                                      parseArgs(rest)
          case rest                => rest
        }
     }
     var flist = parseArgs(args)

     if(passwd.length == 0) {
        passwd = Passwords.getPassword("Password: ", (!decrypt)&&(!check)).getOrElse("")
         
        if (passwd.length == 0) {
           throw new Exception("Password Required!")
        }
     }

     val process = if (check) checkOne(passwd)_ 
                   else if (decrypt) decryptOne(passwd,odir)_  
                   else encryptOne(passwd,odir)_ 

     val printout: String=>Unit = if (flist.isEmpty) (x) => { } else println

     if (flist.isEmpty) { flist = List("-") }
     flist.par.map(process).foreach(printout(_))
  }

}
