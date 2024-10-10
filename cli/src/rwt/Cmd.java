package rwt;

import org.rwtodd.args.*;
import org.rwtodd.crypto.spritz.SpritzCipher;
import org.rwtodd.crypto.spritz.SpritzInputStream;
import org.rwtodd.crypto.spritz.SpritzOutputStream;
import org.rwtodd.crypto.spritz.SpritzHeader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.RandomAccessFile;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 *
 * @author Richard Todd 
 */
public class Cmd {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if(args.length < 1) { 
            System.err.println("Usage: spritz (crypt|hash|repass) ...");
            System.exit(-1);
        }
        try {
            switch(args[0]) {
                case "hash" -> new Hasher().run(args);
                case "crypt" -> new Crypter().run(args);
                case "repass"-> new RePass().run(args);
                default ->
                    System.err.printf("Unknown option <%s>, valid commands are 'hash', 'crypt', and 'repass'\n",args[0]);
            }
        } catch(Exception e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }
    
    
    /** This is a utility function that can be shared by any sub-commands
     * needing to get a password.
     * @param prompt A string to display to the user
     * @param confirm Should it make the user re-type for confirmation?
     * @return the typed string
     */
     public static String getPassword(String prompt, boolean confirm) {
        java.io.Console c = System.console();
        if(c == null) throw new IllegalStateException("Can't ask for password without a console!");
        char[] pwchars = c.readPassword(prompt);
        if(confirm) {
            char[] pwchars2 = c.readPassword("[Confirm] " + prompt);
            if(!Arrays.equals(pwchars, pwchars2)) {
                c.printf("Passwords didn't match!\n\n");
                return getPassword(prompt, confirm);
            }
        }
        return new String(pwchars);
    }

}

class RePass {
    private String oldkey;
    private String newkey;
    
    String repass(File f) {
        SpritzHeader h = new SpritzHeader();
        byte[] headerBytes = new byte[h.getHeaderSize()];

        try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {

            raf.seek(0);
            raf.readFully(headerBytes);
            try (InputStream is = new ByteArrayInputStream(headerBytes)) {
                h.Read(is, oldkey);
            } catch (Exception e) {
                return e.toString();
            }

            try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
                h.setIV(null);  // generate a fresh IV upon write
                h.Write(os, newkey);
                raf.seek(0);
                raf.write(os.toByteArray());
            }
        } catch (Exception e) {
            return e.toString();
        }

        return f.getName();
    }
    
    void run(String[] args) throws IOException {
        final var npassOption = new StringParam(List.of("np"), null, "The new password");
        final var opassOption = new StringParam(List.of("op"), null,  "The old password");
        final var helpOption = new FlagParam(List.of("h", "help"), "Get Help");
        final var op = new Parser(npassOption, opassOption, helpOption);
        try {
          final var files = op.parse(args, 1);

          if(helpOption.getValue()) {
              throw new Exception("Usage ... repass [--np <string>] [--op <string>] files...");
          }

          /* select the work we are going to do */
          oldkey = opassOption.getValue();
          if(oldkey == null) {
              oldkey = Cmd.getPassword("Old Password: ", false);
          }
          
          newkey = npassOption.getValue();
          if(newkey == null) {
              newkey = Cmd.getPassword("New Password: ", true);
          }
          
          files.stream()
                .parallel()
                .map( fn -> repass(new File(fn)))
                .forEach(System.out::println); 
          
      } catch (Exception e) {
          System.err.println(e.getMessage());
          System.err.println("---");
          op.printHelpText(System.err);
      }
  }
    
    
}

class Hasher { 
  private int bits; // how many bits of hash?
  private boolean hex; // display in hex?
  
  private String doOneFile(File f) {
    final StringBuilder answer = new StringBuilder();

    try(FileInputStream fstream = new FileInputStream(f)) {
        
      final byte[] hash = SpritzCipher.hash(bits, fstream);
      if (hex) {
         for(final byte b: hash) { answer.append(String.format("%02x",b)); }
      } else {
         answer.append(java.util.Base64.getEncoder().encodeToString(hash));
      }
      answer.append("  ").append(f.getPath());
    } catch (IOException e) {
      answer.append("error! ").append(e);
    }

    return answer.toString();
  }

  private Stream<File> doOneArgument(final File f) {
      if(!f.exists()) {
        System.err.println(f.getName() + ": File does not exist!"); 
        return Stream.empty();
      }

      if(f.isDirectory()) {
         return Arrays.stream(f.listFiles()).flatMap(this::doOneArgument);
      }
      else {
        return Stream.of(f);
      }
  }

  void run(String[] args) throws IOException {
      final var sizeOption = new IntParam(List.of("s", "size"), 256, "The size of the hash in bits (default 256)");
      final var dispHex = new FlagParam(List.of("hex"), "display hashes as hexadecimal");
      final var helpOption = new FlagParam(List.of("h", "help"), "Get Help");
      final var op = new Parser(sizeOption, dispHex, helpOption);
      try {
          final var files = op.parse(args, 1);

          if(helpOption.getValue()) {
              throw new Exception("Usage ... hash [--size <string>] [--hex] files...");
          }

          bits = sizeOption.getValue();
          hex = dispHex.getValue();
          files.stream()
                .parallel()
                .flatMap(fn -> doOneArgument(new File(fn)))
                .map(this::doOneFile)
                .forEach(System.out::println);
      } catch (Exception e) {
          System.err.println(e.getMessage());
          System.err.println("---");
          op.printHelpText(System.err);
      }
  }
  
  Hasher() {
  }   
}

class Crypter {

  // helper function to fully copy the input to the output
  private static void copyStream(final InputStream is, final OutputStream os) 
    throws IOException {
      final byte[] buffer = new byte[4096];
 
      int count = is.read(buffer,0,buffer.length) ;
      while(count >= 0) {
         os.write(buffer,0,count);
         count = is.read(buffer,0,buffer.length);
      }
  }

  private String key;
  private Optional<Path> odir;
 
  private String decrypt(final File f) {
    final String path = f.getPath();
    String report;
    
    try(final SpritzInputStream spritz = new SpritzInputStream(key, new FileInputStream(f))) {
       final String decryptedName = changedir(spritz.getOriginalName().
                                                  orElse( path.endsWith((".dat")) ? 
                                                                   path.substring(0,path.length() - 4): 
                                                                   path + ".unenc" ));
        report = String.format("%s -> %s",path, decryptedName);
        try(final FileOutputStream ostream = new FileOutputStream(decryptedName)) {
            copyStream(spritz.getInputStream(),ostream);
        }
    } catch (Exception e) {
      report = String.format("%s: error: %s", path, e);
    }

    return report;
  }

  private String check(final File f) {
    final String path = f.getPath();
    String report;
  
    try(final SpritzInputStream spritz = new SpritzInputStream(key, new FileInputStream(f))) {
       final String decryptedName = spritz.getOriginalName().orElse( "<none stored!>" );
       report = String.format("%s is OK, name in file is %s",path, decryptedName);
    } catch (Exception e) {
      report = String.format("%s: error: %s", path, e);
    }

    return report;
  }

  private String encrypt(final File f) {
    final String path = f.getPath();
    final String encryptedName = changedir(pathNoExt(path) + ".dat");
    String report = String.format("%s -> %s",path, encryptedName);
    try(final InputStream istream = new FileInputStream(f);
        final SpritzOutputStream spritz = new SpritzOutputStream(Optional.of(f.getName()), 
                                                                  key, 
                                                                  new FileOutputStream(encryptedName))
       ) {
      copyStream(istream, spritz.getOutputStream());
    } catch (Exception e) {
      report = String.format("%s: error: %s", path, e);
    }

    return report;
  }

  private Stream<File> doOneArgument(final File f) {
      if(!f.exists()) {
        System.err.println(f.getPath() + ": File does not exist!"); 
        return Stream.empty();
      }

      if(f.isDirectory()) {
        return Arrays.stream(f.listFiles()).flatMap(this::doOneArgument);
      }
      else {
        return Stream.of(f);
      }
  }

  Crypter() {
  }
  
  void run(String[] args) throws IOException {
      final var passOption = new StringParam(List.of("p", "password"), null, "the password");
      final var decryptOption = new FlagParam(List.of("d", "decrypt"), "decrypt files instead of encrypting them");
      final var checkOption = new FlagParam(List.of("c", "check"), "just check if the password is correct");
      final var odirOption = new ExistingDirectoryParam(List.of("o", "outdir"), null, "specifies an output directory");
      final var helpOption = new FlagParam(List.of("h", "help"), "Get Help");

      final var op = new Parser(passOption, decryptOption, checkOption, odirOption, helpOption);
      try {
          final var files = op.parse(args, 1);

          if(helpOption.getValue()) {
              throw new Exception("Usage ... crypt [--password <string>] [--decrypt] [--check] [--outdir dir] files...");
          }

          /* select the work we are going to do */
          Function<File,String> worker = this::encrypt;
          if(decryptOption.getValue()) { worker =  this::decrypt; }
          if(checkOption.getValue()) { worker =  this::check; }
          
          key = passOption.getValue();
          if(key == null) { 
              key = Cmd.getPassword("Password: ", !(decryptOption.getValue()||checkOption.getValue()));
          } 

          odir = Optional.ofNullable(odirOption.getValue());
          files.stream()
                .parallel()
                .flatMap(fn -> doOneArgument(new File(fn)))
                .map(worker)
                .forEach(System.out::println); 
          
      } catch (Exception e) {
          System.err.println(e.getMessage());
          System.err.println("---");
          op.printHelpText(System.err);
      }
  }

    private String pathNoExt(final String orig) {
        int dot = orig.lastIndexOf('.');
        if(dot > 0) {
            return orig.substring(0, dot);
        }
        return orig;
    }
    
    private String changedir(final String path) {
          String answer = path;
          if(odir.isPresent()) {
              answer = new File(odir.get().toString(), new File(path).getName()).getPath();
          }
          return answer;
    }

}
