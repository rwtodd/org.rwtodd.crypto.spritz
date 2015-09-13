#ifndef RWT_SPRITZ
#define RWT_SPRITZ

#include<stdint.h>
#include<stdio.h>

struct s_spritz_state; 
typedef struct s_spritz_state *const spritz_state;

/* the main calls ******************************** */
spritz_state create_spritz(void);
void destroy_spritz(spritz_state s);
void spritz_absorb(spritz_state s, const uint8_t b); 
void spritz_absorb_many(spritz_state s, const uint8_t* bytes, size_t len);
void spritz_absorb_stop(spritz_state s);
uint8_t spritz_drip(spritz_state s);
void spritz_drip_many(spritz_state s, uint8_t* arr, size_t len);

/* helper calls ********************************** */
uint8_t* spritz_file_hash(uint8_t bytes, FILE *input);
uint8_t* spritz_string_hash(uint8_t bytes, 
                            const uint8_t * const str, 
                            size_t len);
void destroy_spritz_hash(const uint8_t*const hash);

#endif
