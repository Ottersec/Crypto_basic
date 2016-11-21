/*
 * chiffrement utilisant le ou exclusif
 */
void xor_crypt(char* key, char* texte, char* chiffre);

/*
 * dechiffrement utilisant le ou exclusif
 */
void xor_decrypt(char* key, char* chiffre, char* clair);

/*
 * chiffrement utilisant cesar
 */
void cesar_crypt(int decallage, char* texte, char* chiffre);

/*
 * dechiffrement utilisant  cesar
 */
void cesar_decrypt(int decallage, char* chiffre, char* clair);

/*
 * chiffrement utilisant viginere
 */
void viginere_crypt(char* key, char* texte, char* chiffre);

/*
 * dechiffrement utilisant viginere
 */
void viginere_decrypt(char* key, char* chiffre, char* clair);

/*
 * chiffrement utilisant des ECB
 */
void des_crypt(char* key, char* texte, char* chiffre, int size);


/*
 * dechiffrement utilisant des ECB
 */
void des_decrypt(char* key, char* chiffre, char* clair, int size);

/*
 * chiffrement utilisant des CBC
 */
void des_crypt_cbc(char* vect_init, char* key, char* texte, char* chiffre, int size);

/*
 * dechiffrement utilisant des CBC
 */
void des_decrypt_cbc(char* vect_init, char* key, char* chiffre, char* clair, int size);


/*
 * chiffrement utilisant 3des ECB
 */
void tripledes_crypt(char* key1, char* key2, char* texte, char* chiffre, int size);


/*
 * dechiffrement utilisant 3des ECB
 */
void tripledes_decrypt(char* key1, char* key2, char* chiffre, char* clair, int size);

/*
 * chiffrement utilisant 3des CBC
 */
void tripledes_crypt_cbc(char * vect_init, char* key1, char* key2, char* texte, char* chiffre, int size);

/*
 * dechiffrement utilisant 3des CBC
 */
void tripledes_decrypt_cbc(char * vect_init, char* key1, char* key2, char* chiffre, char* clair, int size);

/*
 * Chiffrement RSA
 */
void rsa_crypt(int e, int n, char* texte, char* chiffre, int size);

/*
 * Dechiffrement RSA
 */
void rsa_decrypt(int d, int n, char* chiffre, char* clair);


/*
 * Calcul du condense MD5 du texte, hash est une chaine hexadecimal
 */
void md5(char * texte, char * hash);

