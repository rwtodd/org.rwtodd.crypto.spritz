/* let's make a quick c-version of
 * the hasher, and see how it compares
 * to the other versions, speed-wise.
 */

#include "spritz.hpp"
#include<cstdint>
#include<iostream>
#include<fstream>
#include<iterator>
#include<iomanip>

static void print_hash(std::ostream &os, 
                       const uint8_t*beg, 
                       const uint8_t* end) {
  auto settings = os.flags();
  os << std::hex << std::setfill('0');
  while(beg != end) { 
    os << std::setw(2) << static_cast<int>(*beg++);
  }
  os.flags(settings);
}

int main(int argc, char **argv) {
  uint8_t hash[32];

  if(argc < 2) {  std::cerr << "Usage: spritz file1 file2...\n"; return -1; }
  for(int idx = 1; idx < argc; ++idx) {
     std::cout << argv[idx] << ": ";
     auto input = std::ifstream(argv[idx], std::ifstream::binary);
     input >> std::noskipws; 
     if(input) {
       spritz::hash(std::istream_iterator<uint8_t>(input),
                    std::istream_iterator<uint8_t>(),
                    hash, 
                    hash+32);
       print_hash(std::cout, hash, hash+32);
       std::cout << std::endl;
     } else {
       std::cerr << "BAD FILE\n";
     }
  }

  return 0;
}
