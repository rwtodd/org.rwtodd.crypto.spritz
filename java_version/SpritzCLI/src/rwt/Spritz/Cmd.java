/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rwt.Spritz;

import com.waywardcode.crypto.SpritzCipher;
import com.waywardcode.crypto.SpritzInputStream;
import com.waywardcode.crypto.SpritzOutputStream;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;
import joptsimple.OptionSpec;

/**
 *
 * @author richa
 */
public class Cmd {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if(args.length < 1) { 
            System.err.println("Usage: spritz (crypt|hash) ...");
        }
        String[] restargs = Arrays.copyOfRange(args,1,args.length);
        try {
            switch(args[0]) {
                case "hash": 
                    new Hasher().run(restargs);
                    break;
                case "crypt":
                    new Crypter().run(restargs);
                    break;
                default:
                    System.err.printf("Unknown option <%s>, valid commands are 'hash' and 'crypt'\n",args[0]);
            }
        } catch(Exception e) {
            System.err.println(e);
        }
    }
    
}

class Hasher { 
  private int bits;
  
  private String doOneFile(File f) {
    final StringBuilder answer = new StringBuilder();
    answer.append(f.getPath()).append(": ");

    try(FileInputStream fstream = new FileInputStream(f)) {

      final byte[] hash = SpritzCipher.hash(bits, fstream);
      for(final byte b: hash) { answer.append(String.format("%02x",b)); }

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
      OptionParser op = new OptionParser();
      try {
          OptionSpec<Integer> sizeOption = op.accepts("s", "the size of the hash in bits").
                                              withRequiredArg().
                                              ofType(Integer.class).
                                              defaultsTo(256);
          OptionSpec<File> files = op.nonOptions("the files to hash").ofType(File.class);
          OptionSet os = op.parse(args);
          bits = os.valueOf(sizeOption);
          files.values(os).stream()
                .parallel()
                .flatMap(this::doOneArgument)
                .map(this::doOneFile)
                .sorted()
                .forEachOrdered(System.out::println);     
      } catch (Exception e) {
          System.err.println(e);
          System.err.println("---");
          op.printHelpOn(System.err);
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
  private Optional<String> odir;
 
  private String decrypt(final File f) {
    final String path = f.getPath();
    String report = "";
    
    try(final SpritzInputStream istream = new SpritzInputStream(key, new FileInputStream(f))) {
       final String decryptedName = changedir(istream.getFname().
                                                  orElse( path.endsWith((".dat")) ? 
                                                                   path.substring(0,path.length() - 4): 
                                                                   path + ".unenc" ));
        report = String.format("%s -> %s",path, decryptedName);
        try(final FileOutputStream ostream = new FileOutputStream(decryptedName)) {
            copyStream(istream,ostream);
        }
    } catch (Exception e) {
      report = String.format("%s: error: %s", path, e);
    }

    return report;
  }

  private String check(final File f) {
    final String path = f.getPath();
    String report = "";
  
    try(final SpritzInputStream istream = new SpritzInputStream(key, new FileInputStream(f))) {
       final String decryptedName = istream.getFname().orElse( "<none stored!>" );
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
        final OutputStream ostream = new SpritzOutputStream(Optional.of(f.getName()), 
                                                            key, 
                                                            new FileOutputStream(encryptedName))
       ) {
      copyStream(istream,ostream);
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
      OptionParser op = new OptionParser();
      try {
          OptionSpec<String> passOption = op.accepts("p", "the password").
                                              withRequiredArg().required().
                                              ofType(String.class);
          OptionSpec decryptOption = op.accepts("d", "decrypt files instead of encrypting them");
          OptionSpec checkOption = op.accepts("c", "just check if you know the password");
          OptionSpec<String> odirOption = op.accepts("o", "specifies the output directory").
                                               withRequiredArg().
                                               ofType(String.class);
          OptionSpec<File> files = op.nonOptions("the files to encrypt").ofType(File.class);
          OptionSet os = op.parse(args);
          
          /* select the work we are going to do */
          Function<File,String> worker = this::encrypt;
          if(os.has(decryptOption)) { worker =  this::decrypt; }
          if(os.has(checkOption)) { worker =  this::check; }
          
          key = os.valueOf(passOption);
           
          if(os.has(odirOption)) {
              odir = Optional.of(os.valueOf(odirOption));
          } else {
              odir = Optional.empty();
          }
          
          files.values(os).stream()
                .parallel()
                .flatMap(this::doOneArgument)
                .map(worker)
                .sorted()
                .forEachOrdered(System.out::println); 
          
      } catch (Exception e) {
          System.err.println(e);
          System.err.println("---");
          op.printHelpOn(System.err);
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
              answer = new File(odir.get(), new File(path).getName()).getPath();
          }
          return answer;
    }

}
