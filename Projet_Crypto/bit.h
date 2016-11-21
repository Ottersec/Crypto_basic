#ifndef BIT_H
#define BIT_H

int bit_get(const unsigned char *bits, int pos);

void bit_set(unsigned char *bits, int pos, int etat);

void bit_xor(const unsigned char *bits1, const unsigned char *bits2, 
             unsigned char *bitsx, int taille);

void bit_rot_left(unsigned char *bits, int taille, int nbre);

#endif
