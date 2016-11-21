#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypt.h"
#include "encrypt.h"
#include <math.h>
#include "md5.h"
#include "bit.h"

/**
 *  * chiffrement utilisant le ou exclusif
 *   */
void xor_crypt(char * key, char * texte, char* chiffre)
{
	int i=0,k=0;
	if(key !=NULL){
		while(texte[i]!='\0'){
			if(key[k]!='\0'){
				chiffre[i]=texte[i]^key[k];
				i++;
				k++;
			}else{
				k=0;
			}
		}
	}
	

}

/**
 *  * déchiffrement utilisant le ou exclusif
 *   */
void xor_decrypt(char * key, char * texte, char* chiffre)
{
	xor_crypt(key,texte,chiffre);
	
}

/**
 *  * chiffrement utilisant cesar
 *   */
void cesar_crypt(int decallage, char * texte, char* chiffre)
{
	int i=0;
	while(texte[i]!='\0'){
		if(texte[i] >='a' && texte[i] <='z'){
			chiffre[i]=(texte[i]-'a'+decallage)%26+'a';
		}
		else if(texte[i] >='A' && texte[i] <='Z'){

			chiffre[i]=(texte[i]-'A'-decallage)%26+'A';
		}else{
			chiffre[i]=texte[i];
		}
		i++;
	}
unsigned char *md5_bis (unsigned char *,md5_size, unsigned char *);
void md5_init (struct md5_ctx *);

}

/**
 *  * déchiffrement utilisant  cesar
 *   */
void cesar_decrypt(int decallage, char * texte, char* chiffre)
{
	int j=0;
	while(texte[j]!='\0'){
		if(texte[j] >='a' && texte[j] <='z'){
			if(texte[j]-'a'<=0)
				chiffre[j]=(texte[j]- 'a' -decallage)%26+'z'+1;
			else
				chiffre[j]=(texte[j]-'a'-decallage)%26+'a';
		}
		else if(texte[j] >='A' && texte[j] <='Z'){

			chiffre[j]=(texte[j]-'A'-decallage)%26+'A';
		}else{
			chiffre[j]=texte[j];
		}
		j++;
	}

}

/**
 *  * chiffrement utilisant v{
iginere
 *   */
void viginere_crypt(char * key, char * texte, char* chiffre)
{
	int k=0,r=0;
	while(texte[k]!='\0'){
		if(key[r]=='\0')
			r=0;
		if(texte[k] >='a' && texte[k] <='z'){
			chiffre[k]=(texte[k]-'a'+(key[r]-'a'))%26+'a';
		}
		else if(texte[k] >='A' && texte[k] <='Z'){
			chiffre[k]=(texte[k]-'A'+(key[r]-'A'))%26+'A';
		}else{
			chiffre[k]=texte[k];
		}
		r++;
		k++;
	}

}

/**
 *  * déchiffrement utilisant viginere
 *   */
void viginere_decrypt(char * key, char * texte, char* chiffre)
{
	int k=0,r=0;
	while(texte[k]!='\0'){
		if(key[r]=='\0')
			r=0;
		if(texte[k] >='a' && texte[k] <='z'){
			if(((texte[k]-(key[r]-'a'))-'a')<=0){
				char rslt=chiffre[k]=(texte[k]- 'a' -(key[r]-'a'))%26+'z'+1;
				texte[k]=rslt;
			}
			else
				chiffre[k]=(texte[k]-'a'-(key[r]-'a'))%26+'a';
		}
		else if(texte[k] >='A' && texte[k] <='Z'){
			chiffre[k]=(texte[k]-'A'-(key[r]-'A'))%26+'A';
		}
		else{
			chiffre[k]=texte[k];
		}
		r++;
		k++;
	}
}

/**
 *  * chiffrement utilisant des
 *   */
void des_crypt(char * key, char * texte, char* chiffre, int size)
{
	int i;
	for(i=0;i<size;i++){
		des_encipher((unsigned char *)texte + 8*i,(unsigned char *)chiffre + 8*i,(unsigned char *)key);
	}

}


/**
 *  * déchiffrement utilisant des
 *   */
void des_decrypt(char * key, char * texte, char* chiffre, int size)
{	
	int i;
	for(i=0;i<size;i++){
		des_decipher((unsigned char *)texte +8*i,(unsigned char*)chiffre +8*i,(unsigned char *) key);
	}

}

/*
 * chiffrement utilisant des CBC
 */
void des_crypt_cbc(char* vect_init, char* key, char* texte, char* chiffre, int size)
{
	char* cbc = (char *)malloc(8*sizeof(char));
	char* vecteur = (char *)malloc(8*sizeof(char));
	memcpy(vecteur,vect_init,8);
	int j=0;
	for (;j< size;j++)
	{
		bit_xor((unsigned char*)(texte+(j*8)),(unsigned char*)vecteur,(unsigned char*)cbc,8*8);
		des_encipher((unsigned char*)cbc,(unsigned char*)chiffre+(j*8),(unsigned char*)key);
		memcpy(vecteur,chiffre+(j*8),8);
	}

}

/*
 * dechiffrement utilisant des CBC
 */
void des_decrypt_cbc(char* vect_init, char* key, char* chiffre, char* clair, int size)
{
	char* vecteur = (char *)malloc(8*sizeof(char));
	memcpy(vecteur,vect_init,8);
	int j=0;
	for (;j<size;j++)
	{
		des_decipher((unsigned char*)(chiffre+(j*8)),(unsigned char*)(clair+(j*8)),(unsigned char*)key);
		bit_xor((unsigned char*)(clair+(j*8)),(unsigned char*)vecteur,(unsigned char*)clair+(j*8), 8*8);
		memcpy(vecteur,chiffre+(j*8),8);
	}
}


/**
 *  * chiffrement utilisant 3des
 *   */
void tripledes_crypt(char * key1, char * key2, char * texte, char* chiffre,int size)
{
	char *chaine_tmp=(char *)malloc(strlen(texte) * sizeof(char));
	strcpy(chaine_tmp,texte);
	
	des_crypt(key1, texte, chiffre, size);
	des_decrypt(key2, chiffre, texte, size);
	des_crypt(key1, texte, chiffre,size);
	
	strcpy(texte,chaine_tmp);
	free(chaine_tmp);
}


/**
 *  * déchiffrement utilisant 3des
 *   */
void tripledes_decrypt(char* key1, char* key2, char* texte, char* chiffre, int size)
{

	des_decrypt(key1, texte, chiffre, size);
	des_crypt(key2, chiffre, texte, size);
	des_decrypt(key1, texte, chiffre,size);
	
}

/*
 * chiffrement utilisant 3des CBC
 */
void tripledes_crypt_cbc(char * vect_init, char* key1, char* key2, char* texte, char* chiffre, int size)
{
	char *chaine_tmp=(char *)malloc(8*size);
	des_crypt_cbc(vect_init,key1,texte,chiffre,size);
	des_decrypt_cbc(vect_init,key2,chiffre,chaine_tmp,size);
	des_crypt_cbc(vect_init,key1,chaine_tmp,chiffre,size);
}


/*
 * dechiffrement utilisant 3des CBC
 */
void tripledes_decrypt_cbc(char * vect_init, char* key1, char* key2, char* chiffre, char* clair, int size)
{
	char *chaine_tmp=(char *)malloc(8*size);
	des_decrypt_cbc(vect_init,key1,chiffre,chaine_tmp,size);
	des_crypt_cbc(vect_init,key2,chaine_tmp,chiffre,size);
	des_decrypt_cbc(vect_init,key1,chiffre,clair,size);
}


/*
 * Calcul du condense MD5 du texte
 */
void md5(char * texte, char * hash)
{
	MD5_To_String((unsigned char *)texte,hash);

}

/****************************************************************
 *                                                               *
 *  -------------------------- modexp -------------------------  *
 *                                                               *
 ****************************************************************/

static Huge modexp(Huge a, Huge b, Huge n) {
	
	Huge               y;
	
	/****************************************************************
	 *                                                               *
	 *  Calcule (pow(a, b) % n) avec la méthode du carré binaire     *
	 *  et de la multiplication.                                     *
	 *                                                               *
	 ****************************************************************/
	
	y = 1;
	
	while (b != 0) {
		
		/*************************************************************
		 *                                                            *
		 *  Pour chaque 1 de b, on accumule dans y.                   *
		 *                                                            *
		 *************************************************************/
		
		if (b & 1)
			y = (y * a) % n;
		
		/*************************************************************
		 *                                                            *
		 *  Élévation de a au carré pour chaque bit de b.             *
		 *                                                            *
		 *************************************************************/
		
		a = (a * a) % n;
		
		/*************************************************************
		 *                                                            *
		 *  On se prépare pour le prochain bit de b.                  *
		 *                                                            *
		 *************************************************************/
		
		b = b >> 1;
		
	}
	
	return y;
	
}


/**
 * Transforme une chaine de caractere en chaine d'entier
 */
void texttoint(char * texte, char* chiffre, int size){
	*chiffre='\0';
	int tmp;
	int i;
	for(i=0;i<size;i++){		
	    // on ajoute 10 pour eviter le probleme de disparition du 0 devnt les entiers entre 1 et 9 (01 a 09)
		// ceci evite de decouper le texte en bloc de taille < n et de les normaliser ensuite
		tmp=(*(texte+i)-'a'+10);
		sprintf(chiffre+strlen(chiffre),"%d%c",tmp,'\0');
	}
}

/**
 * Transforme une chaine d'entier en chaine de caractere
 */ 
void inttotext(char * texte, char* chiffre){
	*chiffre='\0';
	int tmp=0;
	while((*texte) != '\0'){	
	    // lettre de l'alphabet (0..25 correspond pour nous a 10..35)	
		if(10*tmp+(*(texte)-'0') > 36){
		    // on deduit donc 10 pour obtenir la bonne lettre dans l'alphabet
			sprintf(chiffre+strlen(chiffre),"%c%c",tmp+'a'-10, '\0');
			tmp=0;
		}
		tmp=10*tmp+(*(texte)-'0');
		texte++;
	}
}

/**
 * Chiffrement RSA
 */
void rsa_crypt(int e, int n, char * texte, char* chiffre, int size)
{
    int tmp;
	Huge buf=0;
	char* pt;
	char* btmp = (char *)malloc(strlen(texte) * sizeof(char)); 
	
	texttoint(texte,btmp,size);
	pt = btmp;
	*chiffre='\0';
	while((*pt) != '\0'){
		tmp=*pt-'0';
		if(10*buf + tmp >= n){
		    // on utilise le $ comme separateur de bloc
			sprintf(chiffre+strlen(chiffre),"%ld$%c",modexp(buf,e,n) ,'\0');
			buf=0;
		}
		buf=10*buf+tmp;
		pt++;
	}
	sprintf(chiffre+strlen(chiffre),"%ld$%c",modexp(buf,e,n),'\0');
	printf("\n");
}

/**
 * Dechiffrement RSA
 */
void rsa_decrypt(int d, int n, char * texte, char* chiffre)
{
	int tmp;
	char* pt=texte;
	char* tmpc= (char *)malloc(strlen(texte) * sizeof(char)); 
	Huge buf=0;
	
	*tmpc='\0';
	while((*pt) != '\0'){
		// on utilise le $ comme separateur de bloc
	    if((*pt) == '$'){
			sprintf(tmpc+strlen(tmpc),"%ld%c",modexp(buf,d,n),'\0');
			buf=0;
		}else{
			tmp=*pt-'0';
			buf=10*buf+tmp;
		}
		pt++;
	}
	sprintf(tmpc+strlen(tmpc),"%ld%c",modexp(buf,d,n),'\0');
	
	inttotext(tmpc,chiffre);
}


