/****************************************************************
*                                                               *
*  ------------------------ encrypt.h ------------------------  *
*                                                               *
****************************************************************/

#ifndef ENCRYPT_H
#define ENCRYPT_H

/****************************************************************
*                                                               *
*  Dans une implémentation sécurisée, Huge devrait avoir        *
*  au moins 400 chiffres décimaux au lieu des 10 utilisés ici   *
*  (ULONG_MAX = 4294967295).                                    *
*                                                               *
****************************************************************/


typedef unsigned long int Huge;

/****************************************************************
*                                                               *
*  Structure pour les clés publiques RSA.                       *
*                                                               *
****************************************************************/

typedef struct RsaPubKey_ {

Huge               e;
Huge               n;

} RsaPubKey;

/****************************************************************
*                                                               *
*  Structure pour les clés privées RSA.                         *
*                                                               *
****************************************************************/

typedef struct RsaPriKey_ {

Huge               d;
Huge               n;

} RsaPriKey;


/****************************************************************
*                                                               *
*  --------------------  Interface publique  -----------------  *
*                                                               *
****************************************************************/

void des_encipher(const unsigned char *clair, 
                  unsigned char *chiffre, 
                  const unsigned char *cle);

void des_decipher(const unsigned char *texte_chiffre, 
                  unsigned char *texte_clair, 
                  const unsigned char *cle);

void rsa_encipher(Huge texte_clair, Huge *texte_chiffre, 
                  RsaPubKey cle_pub);

void rsa_decipher(Huge texte_chiffre, Huge *texte_clair, 
                  RsaPriKey cle_priv);

Huge gcd ( Huge a, Huge b );

Huge nb_premier(Huge p);

void generator_rsakey(RsaPubKey * kpu, RsaPriKey * kpb , Huge valeurp, Huge valeurq);


#endif
