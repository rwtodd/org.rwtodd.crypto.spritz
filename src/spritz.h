#pragma once

#include<stdint.h>
#include<unistd.h>
#include<stdio.h>

struct s_spritz_state;
typedef struct s_spritz_state *const spritz_state;

/* the main calls ******************************** */
spritz_state create_spritz(void);
void destroy_spritz(spritz_state s);
void spritz_absorb(spritz_state s, const uint8_t b);
void spritz_absorb_many(spritz_state s, const uint8_t * bytes, size_t len);
void spritz_absorb_stop(spritz_state s);
uint8_t spritz_drip(spritz_state s);
void spritz_drip_many(spritz_state s, uint8_t * arr, size_t len);
void spritz_xor_many(spritz_state s, uint8_t * arr, size_t len);

/* helper calls ********************************** */
uint8_t *spritz_file_hash(int fd, size_t bytes);
uint8_t *spritz_mem_hash(const uint8_t * const mem,
			 size_t len, size_t bytes);
void destroy_spritz_hash(const uint8_t * const hash);
spritz_state spritz_crypt(const uint8_t * pw, size_t pwlen,
			  const uint8_t * iv, size_t ivlen);
ssize_t spritz_xor_copy(spritz_state s, int tgt_fd, int src_fd);
