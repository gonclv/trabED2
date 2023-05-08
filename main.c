// comando para compilar: gcc main.c -o main mtwister/libmtwister.a -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/crypto.h"
#include "openssl/sha.h"
#include "mtwister/mtwister.h"

// estruturas de dados
typedef struct BlocoNaoMinerado{
	unsigned short numero;
	unsigned int nonce;
	unsigned char data[184];
	unsigned char hashAnterior[SHA256_DIGEST_LENGTH];
} BlocoNaoMinerado;

typedef struct BlocoMinerado{
	BlocoNaoMinerado bloco;
	unsigned char hash[SHA256_DIGEST_LENGTH];
} BlocoMinerado;

// funcoes e procedimentos
void printHash(unsigned char hash[], int length);
void inicializaBloco(BlocoNaoMinerado* bloco, int numero);

int main(){
	// variavel para gerar numeros aleatorios
	MTRand gerador = seedRand(1234567);

	// criando o bloco genesis
	BlocoNaoMinerado aux;  // bloco auxilar p/ ajudar na mineração
	BlocoMinerado blocoGenesis;
	inicializaBloco(&aux, 1); // preenche com com dados básicos

	// agora, definindo dados específico do bloco gênesis
	char temp[] = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
	strncpy(aux.data, temp, strlen(temp));
	aux.data[183] = genRandLong(&gerador) % 256; // minerador eh aleatorio
	
	// processo de mineracao de fato
	unsigned char hash[SHA256_DIGEST_LENGTH];
	do{
		aux.nonce += 1;
		SHA256((unsigned char*) &aux, sizeof(aux), hash);
	} while(hash[0] != 0);

	// pronto, minerado!
	// ja da pra copiar esse dados para o bloco generis
	blocoGenesis.bloco = aux;
	memcpy(blocoGenesis.hash, hash, SHA256_DIGEST_LENGTH);
	
	printf("Sucesso!\nNonce: %u\nMinerador: %u\n", blocoGenesis.bloco.nonce, (unsigned int)blocoGenesis.bloco.data[183]);
	printHash(blocoGenesis.hash, SHA256_DIGEST_LENGTH);
	
	return 0;
}


void printHash(unsigned char hash[], int length){
	int i;
	for(i=0; i<length; i++){
		printf("%02x", hash[i]);
	}
	printf("\n");
}

void inicializaBloco(BlocoNaoMinerado* bloco, int numero){
	// preenchendo dados básicos
	bloco->numero = numero;
	bloco->nonce = -1; // nonce inicia com -1 pra facilitar a mineracao
	// zerando os campos data e hashAnterior
	memset(bloco->data, 0, 184); 
	memset(bloco->hashAnterior, 0, SHA256_DIGEST_LENGTH);
}
