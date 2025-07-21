#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include "word.h"

#define MESSAGE_LEN 16   // for the experiment test case
#define AD_LEN 1         // for the experiment test case

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  *clen = mlen + CRYPTO_ABYTES;

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
  printstate("final 1st key xor", &s);
  P12f(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  printstate("final 2nd key xor", &s);

   //set tag to the last 2 registers
  
  // STOREBYTES(c, s.x[3], 8);
  // STOREBYTES(c + 8, s.x[4], 8);
  
  
  STOREBYTES(c, s.x[0], 8);
  STOREBYTES(c + 8, s.x[1], 8);
  STOREBYTES(c + 16, s.x[2], 8);
  STOREBYTES(c + 24, s.x[3], 8);
  STOREBYTES(c + 32, s.x[4], 8);

  return 0;
}


int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  const int TAGBYTES = 40;

  if (clen < TAGBYTES) return -1;

  *mlen = clen - TAGBYTES;

  // load key and nonce 
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

  clen -= TAGBYTES;
  while (clen >= ASCON_128_RATE) {
    uint64_t c0 = LOADBYTES(c, 8);
    STOREBYTES(m, s.x[0] ^ c0, 8);
    s.x[0] = c0;
    printstate("insert ciphertext", &s);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    clen -= ASCON_128_RATE;
  }

  uint64_t c0 = LOADBYTES(c, clen);
  STOREBYTES(m, s.x[0] ^ c0, clen);
  s.x[0] = CLEARBYTES(s.x[0], clen);
  s.x[0] |= c0;
  s.x[0] ^= PAD(clen);
  c += clen;
  printstate("pad ciphertext", &s);

  s.x[1] ^= K0;
  s.x[2] ^= K1;
  printstate("final 1st key xor", &s);
  P12f(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  printstate("final 2nd key xor", &s);

  // generate and compare tag 
  uint8_t tag[40];
  STOREBYTES(tag,     s.x[0], 8);
  STOREBYTES(tag + 8, s.x[1], 8);
  STOREBYTES(tag + 16, s.x[2], 8);
  STOREBYTES(tag + 24, s.x[3], 8);
  STOREBYTES(tag + 32, s.x[4], 8);

  int result = 0;
  for (int i = 0; i < TAGBYTES; ++i)
    result |= c[i] ^ tag[i];
  result = (((result - 1) >> 8) & 1) - 1;

  return result;
}


int main() {
    unsigned char key[CRYPTO_KEYBYTES] = {0};
    unsigned char nonce[CRYPTO_NPUBBYTES] = {0};
    unsigned char plaintext[MESSAGE_LEN] = {0};  
    unsigned char ad[AD_LEN] = {0};              

    unsigned char ciphertext[MESSAGE_LEN + CRYPTO_ABYTES] = {0};  
    unsigned char decrypted[MESSAGE_LEN] = {0};                   
    unsigned long long clen = 0, mlen = 0;

    // FOR ENCRYPTION 
    crypto_aead_encrypt(ciphertext, &clen, plaintext, MESSAGE_LEN, ad, AD_LEN, NULL, nonce, key);

    printf("Ciphertext:\n");
    for (size_t i = 0; i < MESSAGE_LEN; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("Tag (40 bytes):\n");
    for (size_t i = MESSAGE_LEN; i < clen; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // FOR DECRYPTION 
    int result = crypto_aead_decrypt(decrypted, &mlen, NULL, ciphertext, clen, ad, AD_LEN, nonce, key);

    if (result == 0) {
        printf("Decryption successful!\n");
        printf("Decrypted plaintext:\n");
        for (size_t i = 0; i < mlen; i++) {
            printf("%02X", decrypted[i]);
        }
        printf("\n");
    } else {
        printf("Decryption failed! Tag verification failed.\n");
    }

    return 0;
}



