#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h" 

/**
 *  *
 *   * Usage : xor_crypt key input_file output_file
 *    *
 *     */
int main(int argc, char *argv[]){
	FILE* pFile;
	long lsize;
	char* texte;
	char* chiffre;
	char* dechiffre;
	int size;

	pFile = fopen( argv[1] , "rb");
	if (pFile == NULL) return 1;

	fseek (pFile, 0 , SEEK_END);  // Obtient la taille du fichier
	lsize = ftell (pFile);
	rewind (pFile);

	texte = (char*) malloc (lsize+1);   //Alloue mémoire pour le tampon, de la taille du fichier
	if (texte ==  NULL) return 2;

	fread (texte, 1, lsize, pFile); // copie fichier vers tampon
	texte[lsize-1]='\0';
        
	size = (strlen(texte)+7)/8;


	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   XOR --------------\n");
	xor_crypt("une cle", texte,chiffre);
	xor_decrypt("une cle", chiffre, dechiffre);
	printf("'%s'\n",chiffre);
	printf("'%s'\n",dechiffre);
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   CESAR --------------\n");
	cesar_crypt(2, texte,chiffre);
	printf("'%s'\n",chiffre);
	cesar_decrypt(2, chiffre, dechiffre);
	printf("'%s'\n",dechiffre);
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   VIGENRE --------------\n");
	viginere_crypt("abc", texte,chiffre);
	viginere_decrypt("abc", chiffre, dechiffre);
	printf("'%s'\n",chiffre);
	printf("'%s'\n",dechiffre);
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   DES --------------\n");
	des_crypt("chabada", texte,chiffre,size);
	des_decrypt("chabada", chiffre, dechiffre, size);
	printf("'%s'\n",chiffre);
	printf("'%s'\n",dechiffre);
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	printf("----------------   DES CBC --------------\n");
	des_crypt_cbc(texte, "chabada", texte,chiffre,size);
	des_decrypt_cbc(texte, "chabada", chiffre, dechiffre, size);
	printf("'%s'\n",chiffre);
	printf("'%s'\n",dechiffre);
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");


	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char)); 
	printf("----------------   3DES --------------\n");
	tripledes_crypt("chabada", "chibidi", texte,chiffre, size);
	tripledes_decrypt("chabada", "chibidi", chiffre, dechiffre, size);
	printf("'%s'\n",chiffre);
	printf("'%s'\n",dechiffre);
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(8+strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(8+strlen(texte) * sizeof(char)); 
	printf("----------------   3DES CBC --------------\n");
	tripledes_crypt_cbc(texte, "chabada", "chibidi", texte,chiffre, size);
	tripledes_decrypt_cbc(texte, "chabada", "chibidi", chiffre, dechiffre, size);
	printf("'%s'\n",chiffre);
	printf("'%s'\n",dechiffre);
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");


	chiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
	dechiffre = (char *)malloc(3*strlen(texte) * sizeof(char)); 
	printf("----------------   RSA --------------\n");
	rsa_crypt(7, 5141, texte, chiffre, strlen(texte));
	rsa_decrypt(4279, 5141,  chiffre, dechiffre);
	printf("'%s'\n",chiffre);
	printf("'%s'\n",dechiffre);
	printf("%s\n", strcmp(texte, dechiffre)==0?"ok":"NON");

	chiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
        dechiffre = (char *)malloc(3*strlen(texte) * sizeof(char));
        printf("----------------   MD5 --------------\n");
	md5(texte,dechiffre);
	printf("'%s'\n",dechiffre);

	fclose (pFile);  // ferme le flux et
	free(texte); // libère espace tampon

	return 0;
}
