package rwt.spritz

// This implementation is copyright 2015 Richard Todd
// The license is GPL, see the LICENSE file in the repository.

object Spritz {

  private val usage = """
Usage: spritz (hash|crypt|repass) [args]

   hash  [-s n] [-h] [files...]
   Compute the hash of the given files

     -h     write the hash in hex, rather than base64
     -s     specify the hash size in bits (default: 256)

   crypt [-d] [-p pw] [files...]
   Encrypt/Decrypt files

     -c     check files against a password
     -d     decrypt files (default is to encrypt)
     -o     specify the output directory (default is same as file)
     -p     specify the password to use 

   repass [-op pw] [-np pw] [files...]
   Change the password of a file, in place.

     -op    specify the old, existing password
     -np    specify the new password to use

"""

  def main(args: Array[String]): Unit = {
     try {
        args.toList match {
          case "hash"  :: rest  => Hash.cmd(rest)
          case "crypt" :: rest  => Crypt.cmd(rest)
          case "repass" :: rest => RePass.cmd(rest)
          case _               => System.err.print(usage)
                                  System.exit(1)
        }
     } catch {
         case e: Exception => System.err.println(e) 
                              e.printStackTrace()
                              System.exit(1)
     }
  }
}
