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

 
  private static void decrypt(final String key, final File f) {
    final String path = f.getPath();
    final String decryptedName = path.substring(0,path.length() - 7);
 
    try(final InputStream istream = new SpritzInputStream(key, new FileInputStream(f));
        final FileOutputStream ostream = new FileOutputStream(decryptedName)
       ) {

      copyStream(istream,ostream);
      System.out.printf("%s -> %s\n",path, decryptedName);

    } catch (IOException e) {
      System.err.println(path + ": error: " + e);
    }
  }

  private static void encrypt(final String key, final File f) {
    final String path = f.getPath();
    final String encryptedName = path + ".spritz";
 
    try(final InputStream istream = new FileInputStream(f);
        final OutputStream ostream = new SpritzOutputStream(key, 
                                                           new FileOutputStream(encryptedName))
       ) {

      copyStream(istream,ostream);
      System.out.printf("%s -> %s\n",path, encryptedName);

    } catch (IOException e) {
      System.err.println(path + ": error: " + e);
    }
  }


  private static void doOneArgument(final String key, final File f) {
      if(!f.exists()) {
        System.err.println(f.getPath() + ": File does not exist!"); 
        return;
      }

      if(f.isDirectory()) {
        Arrays.stream(f.listFiles()).forEach( subfile -> doOneArgument(key, subfile) );
      }
      else {
        if(f.getName().endsWith(".spritz")) {
           decrypt(key,f);
        } else {
           encrypt(key,f);
        }
      }
  }

  public static void main(String[] args) {
      if(args.length < 2) {
        System.err.println("Usage: Crypt <<password>> file1 file2 ...");
        return;
      }
      final String key = args[0];
      Arrays.stream(args).skip(1)
                         .forEach( f -> doOneArgument(key, new File(f)) );
  }

}
