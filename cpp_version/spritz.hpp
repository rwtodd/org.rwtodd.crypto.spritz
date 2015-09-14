#ifndef RWT_SPRITZ
#define RWT_SPRITZ

#include<cstdint>
#include<cstddef>

namespace spritz {

class cipher {
  private:
    uint8_t i, j, k, z, a, w; 
    uint8_t mem[256];

    void update();
    void whip(const int amt);
    void crush();
    void shuffle();
    void absorb_nibble(const uint8_t b);

  public:
    cipher();    
    void absorb(const uint8_t b);
    void absorb_stop();
    uint8_t drip(); 
};

template<typename T>  /* T is input iterator */
void absorb(cipher& s, T start, T end) {
   while(start != end) s.absorb(*start++);
}

template<typename T>  /* T is output iterator */
void squeeze(cipher& s, std::size_t amt, T dest) {
   while(amt--) *dest++ = s.drip();
}

template<typename T>  /* T is random-access iterator */
void squeeze(cipher& s, T dest, T end) {
   squeeze(s, (end-dest), dest);
}

/* helper calls ********************************** */
template<typename OI, typename II>
void hash(std::size_t bytes, II src, II srcend, OI dest) {
  cipher s;
  absorb(s, src, srcend);
  s.absorb_stop();
  s.absorb(static_cast<uint8_t>(bytes));
  squeeze(s, bytes, dest); 
}

template<typename OI, typename II>
void hash(II src, II srcend, OI dest, OI destend) {
  hash((destend-dest), src, srcend, dest);
}

}

#endif
