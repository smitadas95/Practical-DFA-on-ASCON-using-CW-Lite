#ifndef ROUND_H_
#define ROUND_H_

#include "ascon.h"
#include "printstate.h"
// #include "hal.h"
// #include "simpleserial.h"

static inline uint64_t ROR(uint64_t x, int n) {
  return x >> n | x << (-n & 63);
}

static inline void ROUND(state_t* s, uint8_t C) {
  state_t t;
  // addition of round constant 
  s->x[2] ^= C;
  // printstate(" round constant", s); 
  // substitution layer 
  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];
  // start of s-box 
  t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
  t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
  t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
  t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
  t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
  // end of keccak s-box 
  t.x[1] ^= t.x[0];
  t.x[0] ^= t.x[4];
  t.x[3] ^= t.x[2];
  t.x[2] = ~t.x[2];
  // printstate(" substitution layer", &t); //
  // linear diffusion layer //
  s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
  s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
  s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
  s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
  s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
  printstate(" round output", s);
}


static inline void ROUND_last(state_t* s, uint8_t C) {

  state_t t;
  // addition of round constant 
  s->x[2] ^= C;
  printstate(" round constant", s);
  // printstate(" round constant", s); 
  // substitution layer 
  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];

  t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
  t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
  t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
  t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
  t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
  printstate(" substitution layer", &t);

  t.x[1] ^= t.x[0];
  t.x[0] ^= t.x[4];
  t.x[3] ^= t.x[2];
  t.x[2] = ~t.x[2];
  // printstate(" substitution layer", &t); 
  // No linear diffusion layer involved in the last round
  s->x[0] = t.x[0];
  s->x[1] = t.x[1];
  s->x[2] = t.x[2];
  s->x[3] = t.x[3];
  s->x[4] = t.x[4];
  printstate(" round output without the linera diffusion layer", s);
  
}


#endif /* ROUND_H_ */
