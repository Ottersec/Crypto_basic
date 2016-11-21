#ifndef MD5_H
#define MD5_H

#include <assert.h>
#include <stdlib.h>

/* WARNING :
 * This implementation is using 32 bits long values for sizes
 */
typedef unsigned int md5_size;

/* MD5 context */
struct md5_ctx {
	struct {
		unsigned int A, B, C, D; /* registers */
	} regs;
	unsigned char *buf;
	md5_size size;
	md5_size bits;
};

/* Size of the MD5 buffer */
#define MD5_BUFFER 1024

/* Basic md5 functions */
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & (~z)))
#define H(x,y,z) ((x ^ y) ^ z)
#define I(x,y,z) ( y ^ (x +(~z)))

/* Rotate left 32 bits values (words) */
#define ROTATE_LEFT(w,s) ((w << s) | ((w & 0xFFFFFFFF) >> (32 - s)))

#define FF(a,b,c,d,x,s,t) (a = b + ROTATE_LEFT((a + F(b,c,d) + x + t), s))
#define GG(a,b,c,d,x,s,t) (a = b + ROTATE_LEFT((a + G(b,c,d) + x + t), s))
#define HH(a,b,c,d,x,s,t) (a = b + ROTATE_LEFT((a + H(b,c,d) + x + t), s))
#define II(a,b,c,d,x,s,t) (a = b + ROTATE_LEFT((a + I(b,c,d) + x + t), s))

void MD5_To_String (unsigned char * texte, char *hash);
unsigned char *md5_bis (unsigned char *,md5_size, unsigned char *);
void md5_init (struct md5_ctx *);
void md5_update (struct md5_ctx *context);
void md5_final (unsigned char *digest, struct md5_ctx *context);

#endif /* MD5_H */
