/*
20081110
D. J. Bernstein
Public domain.
*/

#ifndef cubehash_h
#define cubehash_h

#include <stdint.h>

typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

typedef struct {
  int hashbitlen;
  int pos; /* number of bits read into x from current block */
  uint32_t x[32];
} hashState;

HashReturn cubehash_init(hashState *state, int hashbitlen);

HashReturn cubehash_update(hashState *state, const BitSequence *data,
                           DataLength databitlen);

HashReturn cubehash_final(hashState *state, BitSequence *hashval);

HashReturn cubehash(int hashbitlen, const BitSequence *data,
                    DataLength databitlen, BitSequence *hashval);

#endif
