#ifndef BLAKE256_H_
#define BLAKE256_H_

void blake256_hash( unsigned char *out, const unsigned char *in,
                    unsigned long long inlen );

#endif /* BLAKE256_H_ */
