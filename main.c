#include <stdio.h>
#include <string.h>
#include "openssl/crypto.h"
#include "openssl/sha.h"
#include "mtwister.h"

typedef struct BlocoNaoMinerado{
	unsigned short numero;
	unsigned int nonce;
	unsigned char data[184];
	unsigned char hashAnterior[SHA256_DIGEST_LENGTH];
} BlocoNaoMinerado;

void printHash(unsigned char hash[], int length){
	int i;
	printf("Hash: ");
	for(i=0; i<length; i++){
		printf("%02x", hash[i]);
	}
	printf("\n");
}

int main(){
	// variavel para gerar numeros aleatorios
	MTRand gerador = seedRand(1234567);
		
	// criando bloco a ser usado para geracao do hash
	BlocoNaoMinerado bloco;
	// criando o primeiro bloco - genesis
	bloco.numero = 1;
	bloco.nonce = -1; // nonce inicia com -1 pra facilitar a mineracao
	// definindo dados de bloco.data
	memset(bloco.data, 0, 184); // todas as posicoes passam a valer 0
	char temp[] = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
	strncpy(bloco.data, temp, strlen(temp));
	bloco.data[183] = genRandLong(&gerador) % 256; // minerador eh aleatorio
	// hash anterior: inicialmente nulo
	memset(bloco.hashAnterior, 0, SHA256_DIGEST_LENGTH);
	
	// processo de miniracao desse bloco	
	unsigned char hash[SHA256_DIGEST_LENGTH];
	do{
		bloco.nonce += 1;
		SHA256((unsigned char*)&bloco, sizeof(bloco), hash);
	} while(hash[0] != 0);
	
	printf("Sucesso!\nNonce: %u\nMinerador: %u\n", bloco.nonce, (unsigned int)bloco.data[183]);
	printHash(hash, SHA256_DIGEST_LENGTH);
	
	return 0;
}
