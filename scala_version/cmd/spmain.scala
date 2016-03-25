package rwt.spritz

// This implementation is copyright 2015 Richard Todd
// The license is GPL, see the LICENSE file in the repository.

object Spritz {

  private val usage = """
Usage: spritz (hash|crypt) [args]

   hash  [-s] [files...]
   Compute the hash of the given files

     -s     specify the hash size in bits

   crypt [-d] [-p pw] [files...]
   Encrypt/Decrypt files

     -d     decrypt files (default is to encrypt)
     -o     specify the output directory (default is same as file)
     -p     specify the password to use 

"""

  def main(args: Array[String]): Unit = {
     try {
        args.toList match {
          case "hash"  :: rest => Hash.cmd(rest)
          case "crypt" :: rest => Crypt.cmd(rest)
          case _               => System.err.print(usage)
                                  System.exit(1)
        }
     } catch {
         case e: Exception => System.err.println(e) 
                              System.exit(1)
     }
  }
}
