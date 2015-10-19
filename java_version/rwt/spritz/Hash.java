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
import java.util.stream.Stream;

public class Hash {
 
  private static String doOneFile(File f) {
    final StringBuilder answer = new StringBuilder();
    answer.append(f.getPath()).append(": ");

    try(FileInputStream fstream = new FileInputStream(f)) {

      final byte[] hash = SpritzCipher.hash(256, fstream);
      for(final byte b: hash) { answer.append(String.format("%02x",b)); }

    } catch (IOException e) {
      answer.append("error! ").append(e);
    }

    return answer.toString();
  }

  private static Stream<File> doOneArgument(final File f) {
      if(!f.exists()) {
        System.err.println(f.getName() + ": File does not exist!"); 
        return Stream.empty();
      }

      if(f.isDirectory()) {
         return Arrays.stream(f.listFiles()).flatMap(Hash::doOneArgument);
      }
      else {
        return Stream.of(f);
      }
  }

  public static void main(String[] args) {
      Arrays.stream(args)
            .parallel()
            .flatMap(arg  -> doOneArgument(new File(arg)))
            .map(Hash::doOneFile)
            .sorted()
            .forEachOrdered(System.out::println);
  }

}
