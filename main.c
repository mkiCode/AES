//#pragma once
#include <stdio.h>
#include <stdint.h>
#include "aes.h"
char* get_string(int length);
int main(int argc, char* argv[]) 
{

	uint8_t i;
	FILE* f =  fopen("./key.bin","rb");
	uint8_t key[256/8];
	fread(key, sizeof(key), 1, f);

	//PRINT HEX KEY
	printf("Hex Key(size:%dbits):\n", sizeof(key)*8);
	for (i = 0; i < 4; i++)
		printf("%3x %3x %3x %3x ", key[4*i+0], key[4*i+1], key[4*i+2], key[4*i+3]);
	printf("\n");

	//GET MESSAGE STRING
	printf("getting message string...");
	uint8_t* input = get_string(16);
	//OUTPUT INITIALIZATION
	uint8_t out[16]; // 128

	uint8_t *w; // expanded key
	printf("enter aes init\n");
	w = aes_init(sizeof(key));
	printf("exit aes init\n");

	printf("enter aes key expansion\n");
	aes_key_expansion(key, w);
	




	printf("Plaintext string:\n");
		for(i = 0; i < 16; i++)
			printf("[%c] ", input[i]);
	printf("\n");

	printf("Plaintext message:\n");
	for (i = 0; i < 4; i++)
		printf("%3x %3x %3x %3x ", input[4*i+0], input[4*i+1], input[4*i+2], input[4*i+3]);
	printf("\n");

	aes_cipher(input /* in */, out /* out */, w /* expanded key */);

	printf("Ciphered string:\n");
	for(i = 0; i < 16; i++)
		printf("[%c] ", out[i]);
	printf("\n");

	printf("Ciphered bytes:\n");
	for (i = 0; i < 4; i++)
		printf("%3x %3x %3x %3x ", out[4*i+0], out[4*i+1], out[4*i+2], out[4*i+3]);
	printf("\n");

	aes_inv_cipher(out, input, w);

	printf("Deciphered string:\n");
	for(i = 0; i < 16; i++)
		printf("[%c] ", input[i]);
	printf("\n");

	printf("Deciphered bytes (after inv cipher):\n");
	for (i = 0; i < 4; i++)
		printf("%3x %3x %3x %3x ", input[4*i+0], input[4*i+1], input[4*i+2], input[4*i+3]);

	printf("\n");

	free(w);

	return 0;
}
char* get_string(int length)
{
	printf("enter a 15 char string:\n");
	char* input =  malloc(sizeof(char)*length);
	
	//BUILD FORMAT STRING
	char str[100];
	sprintf(str, "%d", length);
	char format[100];
	format[0] = '%';
	int i;
	for(i = 0;  str[i]!='\0'; i++)
		format[i+1] = str[i];
	format[i+1] = 'c';
	format[i+2]  = '\0';

	//char format[5] = {'%',str[0], str[1], 'c', '\0'};// ONLY WORKS FOR TWO DIGITS
	fscanf(stdin, format, input);
	input[length-1] = '\0';
	printf("return input\n");
	return input;
}
