package rwt.spritz

object Passwords {

  def getPassword(prompt: String, confirm: Boolean): Option[String] = {
     val c = System.console()
     if (c == null) { return None }

     val chrs = c.readPassword(prompt)
     if(confirm) {
         val rpt = c.readPassword("[Confirm] " + prompt)
         if(!rpt.sameElements(chrs)) {
	     c.printf("Passwords don't match!\n\n")
	     return getPassword(prompt, confirm)
	 }
     }
     Some(new String(chrs))
  }

}