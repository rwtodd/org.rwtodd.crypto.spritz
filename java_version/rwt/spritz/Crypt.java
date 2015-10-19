// A Spritz Cipher driver program to encrypt or decrypt files. 

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

package rwt.spritz;

import com.waywardcode.crypto.SpritzInputStream;
import com.waywardcode.crypto.SpritzOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.stream.Stream;

public class Crypt {

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

 
  private static String decrypt(final String key, final File f) {
    final String path = f.getPath();
    final String decryptedName = path.substring(0,path.length() - 7);
    String report = String.format("%s -> %s",path, decryptedName);
 
    try(final InputStream istream = new SpritzInputStream(key, new FileInputStream(f));
        final FileOutputStream ostream = new FileOutputStream(decryptedName)
       ) {

      copyStream(istream,ostream);

    } catch (IOException e) {
      report = String.format("%s: error: %s", path, e);
    }

    return report;
  }

  private static String encrypt(final String key, final File f) {
    final String path = f.getPath();
    final String encryptedName = path + ".spritz";
    String report = String.format("%s -> %s",path, encryptedName);
     
    try(final InputStream istream = new FileInputStream(f);
        final OutputStream ostream = new SpritzOutputStream(key, 
                                                           new FileOutputStream(encryptedName))
       ) {

      copyStream(istream,ostream);

    } catch (IOException e) {
      report = String.format("%s: error: %s", path, e);
    }

    return report;
  }

  private static String doOneFile(final String key, final File f) {
        String answer;
        if(f.getName().endsWith(".spritz")) {
           answer = decrypt(key,f);
        } else {
           answer = encrypt(key,f);
        }
        return answer;
  }

  private static Stream<File> doOneArgument(final File f) {
      if(!f.exists()) {
        System.err.println(f.getPath() + ": File does not exist!"); 
        return Stream.empty();
      }

      if(f.isDirectory()) {
        return Arrays.stream(f.listFiles()).flatMap(Crypt::doOneArgument);
      }
      else {
        return Stream.of(f);
      }
  }

  public static void main(String[] args) {
      if(args.length < 2) {
        System.err.println("Usage: Crypt <<password>> file1 file2 ...");
        return;
      }
      final String key = args[0];
      Arrays.stream(args)
            .skip(1)
            .parallel()
            .flatMap(arg -> doOneArgument(new File(arg)))
            .map(f -> doOneFile(key, f))
            .sorted()
            .forEachOrdered(System.out::println);
  }

}
