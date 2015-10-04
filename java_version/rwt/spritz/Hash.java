// A Spritz Cipher driver program to hash files. 

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
import java.io.IOException;
import java.io.File;
import java.util.Arrays;

public class Hash {
 
  private static void doOneFile(File f) {
    try(FileInputStream fstream = new FileInputStream(f)) {

      final byte[] answer = SpritzCipher.hash(256, fstream);
      System.out.printf("%s: ",f.getPath());
      for(final byte b: answer) { System.out.printf("%02x",b); }
      System.out.println();

    } catch (IOException e) {
      System.err.println(f.getPath() + ": error: " + e);
    }
  }

  private static void doOneArgument(final File f) {
      if(!f.exists()) {
        System.err.println(f.getName() + ": File does not exist!"); 
        return;
      }

      if(f.isDirectory()) {
         Arrays.stream(f.listFiles()).forEach(Hash::doOneArgument);
      }
      else {
        doOneFile(f);
      }
  }

  public static void main(String[] args) {
      Arrays.stream(args).forEach(arg  -> doOneArgument(new File(arg)) );
  }

}
