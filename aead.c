#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include "word.h"
//#include "hal.h"
//#include "simpleserial.h"



int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;


   *clen = mlen + CRYPTO_ABYTES;
  // *clen = mlen + 40;

  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);
  

  state_t s;
  s.x[0] = ASCON_128_IV;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  printstate("init 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  printstate("init 2nd key xor", &s);

  if (adlen) {

    while (adlen >= ASCON_128_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      printstate("absorb adata", &s);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }

    s.x[0] ^= LOADBYTES(ad, adlen);
    s.x[0] ^= PAD(adlen);
    printstate("pad adata", &s);
    P6(&s);
  }

  s.x[4] ^= 1;
  printstate("domain separation", &s);


  while (mlen >= ASCON_128_RATE) {
    s.x[0] ^= LOADBYTES(m, 8);
    STOREBYTES(c, s.x[0], 8);
    printstate("absorb plaintext", &s);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }

  s.x[0] ^= LOADBYTES(m, mlen);
  STOREBYTES(c, s.x[0], mlen);
  s.x[0] ^= PAD(mlen);
  c += mlen;
  printstate("pad plaintext", &s);


  s.x[1] ^= K0;
  s.x[2] ^= K1;
  //printstate("final 1st key xor", &s);
  P12f(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  printstate("final 2nd key xor", &s);

 
  //STOREBYTES(c, s.x[3], 8);
  //STOREBYTES(c + 8, s.x[4], 8);
  
  uint64_t out_state[5] = {s.x[0], s.x[1], s.x[2], s.x[3], s.x[4]};

  STOREBYTES(c, out_state[0], 8);
  STOREBYTES(c + 8, out_state[1], 8);
  STOREBYTES(c + 16, out_state[2], 8);
  STOREBYTES(c + 24, out_state[3], 8);
  STOREBYTES(c + 32, out_state[4], 8);

  return 0;
}



