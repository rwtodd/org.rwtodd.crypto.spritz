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

public class Hash {
 
  private static void doOne(String fname) 
    throws java.io.IOException {
      FileInputStream fstream = new FileInputStream(fname);
      byte[] answer = SpritzCipher.hash(256, fstream);
      fstream.close();
   
      System.out.printf("%s: ",fname);
      for(byte b: answer) { System.out.printf("%02x",b); }
      System.out.println();
  }

  public static void main(String[] args) throws java.io.IOException {
      for(String arg: args) {
         doOne(arg);
      }
  }

}
