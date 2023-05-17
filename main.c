// comando para compilar: gcc main.c -o main mtwister/libmtwister.a -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/crypto.h"
#include "openssl/sha.h"
#include "mtwister/mtwister.h"

// << ESTRUTURAS DE DADOS UTILIZADAS: >>
typedef struct BlocoNaoMinerado{
	unsigned int numero;
	unsigned int nonce;
	unsigned char data[184];
	unsigned char hashAnterior[SHA256_DIGEST_LENGTH];
} BlocoNaoMinerado;

typedef struct BlocoMinerado{
	BlocoNaoMinerado bloco;
	unsigned char hash[SHA256_DIGEST_LENGTH];
} BlocoMinerado;

typedef struct TNo {
	//unsigned int qtdDeBitcoins;
	unsigned short indice;
	struct TNo *prox;
} TNo;


// << FUNCOES E PROCEDIMENTOS >>
void inicializaBloco(BlocoNaoMinerado* bloco, unsigned char hashAnterior[SHA256_DIGEST_LENGTH]);
void gerarBlocoGenesis(BlocoMinerado blocoMinerados[], unsigned int *carteira, MTRand *gerador);
void removeLista(TNo **lista, unsigned short k);
void insereLista(TNo **lista, unsigned short k);
int contaLista(TNo *lista);
unsigned char geraOrigem(unsigned int *carteira, TNo *usuariosComBitcoins, MTRand *gerador);
int busca(TNo *usuariosComBitcoins, int indice);
void atualizaLista(TNo **lista, unsigned int carteira[]);
void escreveArquivo(FILE *arquivo, BlocoMinerado* dados);
void converteParaTXT(FILE *arquivo);

int main(){
	// << PRINCIPAIS VARIAVEIS >>

	// variavel para gerar numeros aleatorios
	MTRand gerador = seedRand(1234567);
	// lista encadeada para controlar usuários de saldo positivo	
	TNo *usuariosComBitcoins = NULL;
	// carteira com todos os endereços de usuários
	unsigned int carteira[256] = {0};
	// vetor para armazenar blocos minerados
	BlocoMinerado blocosMinerados[16];
	// arquivo final contendo os registros da blockchain
	FILE *pArquivo = fopen("blockchain.bin", "w+");
	if(!pArquivo) exit(1);

	// << PROCESSO DE MINERACAO >>

	// criando bloco genesis
	gerarBlocoGenesis(blocosMinerados, carteira, &gerador);
	// apos cada alteracao na carteira, alteramos tambem a lista
	atualizaLista(&usuariosComBitcoins, carteira);

	// VARIAVEIS AUXILIARES:
	BlocoNaoMinerado blocoAux;
	int contadorBlocos = 2; // contaremos do bloco 2 ao 30.000
	int index = 1; // auxilia na gravacao dos blocos no vetor
	unsigned char hashDoAnterior[SHA256_DIGEST_LENGTH];
	// copiando hash do genesis
	memcpy(hashDoAnterior, blocosMinerados[0].hash, SHA256_DIGEST_LENGTH);

	for(; contadorBlocos <= 16; contadorBlocos++){
		// primeiro iniciamos um novo bloco, enviando o hash do anterior
		inicializaBloco(&blocoAux, hashDoAnterior);

		// gerando dados aleatorios
		int quantTransacoes = genRandLong(&gerador) % 62;
		for(int j = 0; j < quantTransacoes; j++) {

			unsigned char indiceOrigem = geraOrigem(carteira, usuariosComBitcoins, &gerador);
			blocoAux.data[3*j] = indiceOrigem;
			blocoAux.data[3*j + 1] = genRandLong(&gerador) % 256;
			blocoAux.data[3*j + 2] = genRandLong(&gerador) % (carteira[indiceOrigem] + 1);
			
			// alterando a carteira			
			carteira[indiceOrigem] -= blocoAux.data[3*j + 2];
			carteira[blocoAux.data[3*j + 1]] += blocoAux.data[3*j + 2];
		}

		// gerando endereço do minerador e concedendo 50 bitcoins
		blocoAux.data[183] = genRandLong(&gerador) % 256;
		carteira[blocoAux.data[183]] = carteira[blocoAux.data[183]] + 50;
		
		// processo de mineracao de fato
		unsigned char hashGerado[SHA256_DIGEST_LENGTH];
		do{
			blocoAux.nonce += 1;
			SHA256((unsigned char*) &blocoAux, sizeof(blocoAux), hashGerado);
		} while(hashGerado[0] != 0);

		// pronto, minerado!
		// ja da pra copiar esse dados no vetor, na posicao correta
		blocosMinerados[index].bloco = blocoAux; 
		memcpy(blocosMinerados[index].hash, hashGerado, SHA256_DIGEST_LENGTH);
		// necessario atualizar a lista novamente
		atualizaLista(&usuariosComBitcoins, carteira);
		// atualizando hashDoAnterior
		memcpy(hashDoAnterior, hashGerado, SHA256_DIGEST_LENGTH);
		index++;
		
		// checando se ja pode escrever no arquivo
		if(index == 16){
			escreveArquivo(pArquivo, blocosMinerados);
			index = 0; // reinicia o index
		}
	}

	converteParaTXT(pArquivo);
	fclose(pArquivo);
	return 0;
}

// funcao que inicializa um bloco com valores iniciais, alem de copiar nesse bloco o hash do anterior
void inicializaBloco(BlocoNaoMinerado* bloco, unsigned char hashAnterior[SHA256_DIGEST_LENGTH]){
	// preenchendo dados básicos
	static int numero = 1;
	bloco->numero = numero;
	numero++;
	bloco->nonce = -1; // nonce inicia com -1 pra facilitar a mineracao
	// zerando campo data
	for(int i=0; i<184; i++){
		bloco->data[i] = 0;
	}
	// copiando hashAnterior
	memcpy(bloco->hashAnterior, hashAnterior, SHA256_DIGEST_LENGTH);
}

// funcao que insere um usuario(endereco da carteira) na lista
void insereLista(TNo **lista, unsigned short k){
    // insere no inicio
	TNo *novo = (TNo*) malloc(sizeof(TNo));
	if(!novo) return;

	novo->indice = k;
	//novo->qtdDeBitcoins = saldo;
	novo->prox = *lista;
	*lista = novo;
}

// funcao que retorna o numero de elemento na lista
int contaLista(TNo *lista){
	if(!lista) return 0;
	else 
		return 1 + contaLista(lista->prox);
}

// funcao que remove um determinado usuario(endereco da carteira) da lista
void removeLista(TNo **lista, unsigned short k){
    // caso base: se a lista for vazia, ou se ponteiro for nulo
    if(!*lista)
        return;

    // caso encontramos o k
    if((*lista)->indice == k){
        TNo *aux = *lista;
        (*lista) = (*lista)->prox;
        free(aux);
    }
    else{
        removeLista(&((*lista)->prox), k);
    }
}

// funcao que verifica se um determinado usuario(endereco da carteira) esta na lista
int busca(TNo *usuariosComBitcoins, int indice) {
	while(usuariosComBitcoins) {
		if(usuariosComBitcoins->indice == indice) return 1;
		usuariosComBitcoins = usuariosComBitcoins->prox;
	}
	return 0;
}

/* Funcao que gera o bloco genesis, levando em consideracoes suas peculiaridades.
   Ademais, insere esse bloco no inicio do vetor de blocos minerados, para dar inicio
   ao processo de mineracao dos demais.
*/
void gerarBlocoGenesis(BlocoMinerado blocoMinerados[], unsigned int *carteira, MTRand *gerador)
{
    BlocoNaoMinerado blocoAux;
	BlocoMinerado blocoGenesis;

	unsigned char hashNulo[SHA256_DIGEST_LENGTH] = {0};  //zera o vetor para ser usado como hash anterior do bloco genesis
	inicializaBloco(&blocoAux, hashNulo);  //preenche os campos do bloco de forma genérica
	
	// agora, definindo dados específico do bloco gênesis
	char temp[] = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
	strncpy(blocoAux.data, temp, strlen(temp));  //adiciona a string acima no campo data da struct
	blocoAux.data[183] = genRandLong(gerador) % 256; // minerador eh aleatorio 
	carteira[blocoAux.data[183]] = 50;

	// processo de mineracao de fato
	unsigned char hashGerado[SHA256_DIGEST_LENGTH];
	do{
		blocoAux.nonce += 1;
		SHA256((unsigned char*) &blocoAux, sizeof(blocoAux), hashGerado);
	} while(hashGerado[0] != 0);
	// pronto, minerado!
	// ja da pra copiar esse dados para o bloco generis
	blocoGenesis.bloco = blocoAux;
	memcpy(blocoGenesis.hash, hashGerado, SHA256_DIGEST_LENGTH);

	// colocando no vetor
	blocoMinerados[0] = blocoGenesis;
}

/* Funcao que gera aleatoriamente o endereco de origem da transacao, dados os 
   usuarios(enderecos da carteira) contidos na lista.
*/
unsigned char geraOrigem(unsigned int *carteira, TNo *usuariosComBitcoins, MTRand *gerador) {
	int quantidadeLista = contaLista(usuariosComBitcoins);
	if(!quantidadeLista) return -1;
	// se tiver apenas um elemento na lista, retorna ele
	if(quantidadeLista == 1) return usuariosComBitcoins->indice;

	// senao, sorteia
	int numeroGerado = genRandLong(gerador) % quantidadeLista ;
	while(numeroGerado--)
		usuariosComBitcoins = usuariosComBitcoins->prox;
	return usuariosComBitcoins->indice;
}


// funcao que atualiza a lista, inserindo ou retirando usuarios(enderecos da carteira)
void atualizaLista(TNo **lista, unsigned int carteira[]){
	for(int i=0; i<256; i++){
			// quem tem saldo positivo, deve permanecer na lista
			if(carteira[i] > 0){
				// se nao estiver na lista, adiciona
				if(!busca(*lista, i)){
					insereLista(lista, i);
				}
			} else{
				if(busca(*lista, i)){
					removeLista(lista, i);
				}
			}
	}
}

// funcao que escreve 16 blocos minerados no arquivo final
void escreveArquivo(FILE *arquivo, BlocoMinerado* dados){
	fwrite(dados, sizeof(BlocoMinerado), 16, arquivo);
}

void converteParaTXT(FILE *arquivo){
	if(!arquivo) return;
	FILE *arqDest = fopen("blockchain.txt", "w");
	if(!arqDest) return;

	BlocoMinerado buffer[16];
	int i, j;
	rewind(arquivo);
	while(!feof(arquivo)){
		fread(buffer, sizeof(BlocoMinerado), 16, arquivo);
		for(i=0; i<16; i++){
			fprintf(arqDest, "Bloco %d\nNonce: %d\nData: ", buffer[i].bloco.numero, buffer[i].bloco.nonce);
			for(j=0; j<184; j++){
				fprintf(arqDest, "%d", buffer[i].bloco.data[j]);
			}
			fprintf(arqDest, "\nHash Anterior: ");
			for(j=0; j<SHA256_DIGEST_LENGTH; j++){
				fprintf(arqDest, "%02x", buffer[i].bloco.hashAnterior[j]);
			}
			fprintf(arqDest, "\nHash: ");
			for(j=0; j<SHA256_DIGEST_LENGTH; j++){
				fprintf(arqDest, "%02x", buffer[i].hash[j]);
			}
			fprintf(arqDest, "\n");
		}
	}

	fclose(arqDest);
}