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

import com.waywardcode.crypto.SpritzCipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.File;
import java.util.Arrays;

public class Crypt {
 
  private static void decrypt(final String key, final File f) {
    final String path = f.getPath();
    final String decryptedName = path.substring(0,path.length() - 7);
 
    try(final FileInputStream istream = new FileInputStream(f);
        final FileOutputStream ostream = new FileOutputStream(decryptedName)
       ) {

      SpritzCipher.decrypt(key, istream, ostream);
      System.out.printf("%s -> %s\n",path, decryptedName);

    } catch (IOException e) {
      System.err.println(path + ": error: " + e);
    }
  }

  private static void encrypt(final String key, final File f) {
    final String path = f.getPath();
    final String encryptedName = path + ".spritz";
 
    try(final FileInputStream istream = new FileInputStream(f);
        final FileOutputStream ostream = new FileOutputStream(encryptedName)
       ) {

      SpritzCipher.encrypt(key, istream, ostream);
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
