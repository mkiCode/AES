
#include "gmult.h"
#include "aes.h"

/* The cipher Key.*/
int K;

/*Number of columns (32-bit words) comprising the State. For this standard, Nb = 4.*/
int Nb = 4;

/*Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4, 6, or 8.*/
int Nk;

/*Number of rounds, which is a function of  Nk  and  Nb (which is fixed). For this standard, Nr = 10, 12, or 14.*/
int Nr;

//Addition in GF(2^8) http://en.wikipedia.org/wiki/Finite_field_arithmetic
uint8_t gadd(uint8_t a, uint8_t b) {return a^b;}

//Subtraction in GF(2^8) http://en.wikipedia.org/wiki/Finite_field_arithmetic
uint8_t gsub(uint8_t a, uint8_t b) {return a^b;}

//Addition of 4 byte words m(x) = x4+1
void coef_add(uint8_t a[], uint8_t b[], uint8_t d[]) 
{
	d[0] = a[0]^b[0];
	d[1] = a[1]^b[1];
	d[2] = a[2]^b[2];
	d[3] = a[3]^b[3];
}

/*Multiplication of 4 byte words m(x) = x4+1*/
void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) 
{
	d[0] = gmult(a[0],b[0])^gmult(a[3],b[1])^gmult(a[2],b[2])^gmult(a[1],b[3]);
	d[1] = gmult(a[1],b[0])^gmult(a[0],b[1])^gmult(a[3],b[2])^gmult(a[2],b[3]);
	d[2] = gmult(a[2],b[0])^gmult(a[1],b[1])^gmult(a[0],b[2])^gmult(a[3],b[3]);
	d[3] = gmult(a[3],b[0])^gmult(a[2],b[1])^gmult(a[1],b[2])^gmult(a[0],b[3]);
}

//Generates the round constant Rcon[i]
uint8_t R[] = {0x02, 0x00, 0x00, 0x00};
 
uint8_t * Rcon(uint8_t i) 
{
	if (i == 1) 
		R[0] = 0x01; // x^(1-1) = x^0 = 1
	else if (i > 1) 
	{
		R[0] = 0x02;
		i--;
		while (i > 1) 
		{
			R[0] = gmult(R[0], 0x02);
			i--;
		}
	}
	return R;
}

/*
 * Transformation in the Cipher and Inverse Cipher in which a Round 
 * Key is added to the State using an XOR operation. The length of a 
 * Round Key equals the size of the State (i.e., for Nb = 4, the Round 
 * Key length equals 128 bits/16 bytes).
 */
void add_round_key(uint8_t *state, uint8_t *w, uint8_t r) 
{
	uint8_t c;
	for (c = 0; c < Nb; c++) {
		state[Nb*0+c] = state[Nb*0+c]^w[4*Nb*r+4*c+0];   //debug, so it works for Nb !=4 
		state[Nb*1+c] = state[Nb*1+c]^w[4*Nb*r+4*c+1];
		state[Nb*2+c] = state[Nb*2+c]^w[4*Nb*r+4*c+2];
		state[Nb*3+c] = state[Nb*3+c]^w[4*Nb*r+4*c+3];	
	}
}

/*
 * Transformation in the Cipher that takes all of the columns of the 
 * State and mixes their data (independently of one another) to 
 * produce new columns.
 */
void mix_columns(uint8_t *state) {

	uint8_t a[] = {0x02, 0x01, 0x01, 0x03}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < Nb; j++) 
	{
		for (i = 0; i < 4; i++) 
			col[i] = state[Nb*i+j];
		

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) 
			state[Nb*i+j] = res[i];
		
	}
}

/*Transformation in the Inverse Cipher that is the inverse of MixColumns().*/
void inv_mix_columns(uint8_t *state) 
{
	uint8_t a[] = {0x0e, 0x09, 0x0d, 0x0b}; // a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < Nb; j++) 
	{
		for (i = 0; i < 4; i++)
			col[i] = state[Nb*i+j];

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++)
			state[Nb*i+j] = res[i];
	}
}

/*
 * Transformation in the Cipher that processes the State by cyclically 
 * shifting the last three rows of the State by different offsets. 
*/
void shift_rows(uint8_t *state) {

	uint8_t i, k, s, tmp;

	for (i = 1; i < 4; i++) 
	{
		// shift(1,4)=1; shift(2,4)=2; shift(3,4)=3
		// shift(r, 4) = r;
		s = 0;
		while (s < i) 
		{
			tmp = state[Nb*i+0];
			
			for (k = 1; k < Nb; k++)
				state[Nb*i+k-1] = state[Nb*i+k];

			state[Nb*i+Nb-1] = tmp;
			s++;
		}
	}
}

/*Transformation in the Inverse Cipher that is the inverse of ShiftRows().*/
void inv_shift_rows(uint8_t *state) 
{
	uint8_t i, k, s, tmp;

	for (i = 1; i < 4; i++) 
	{
		s = 0;
		while (s < i) 
		{
			tmp = state[Nb*i+Nb-1];
			
			for (k = Nb-1; k > 0; k--)
				state[Nb*i+k] = state[Nb*i+k-1];

			state[Nb*i+0] = tmp;
			s++;
		}
	}
}

/*
 * Transformation in the Cipher that processes the State using a non­
 * linear byte substitution table (S-box) that operates on each of the 
 * State bytes independently. 
 */
void sub_bytes(uint8_t *state) 
{
	uint8_t i, j;
	
	for (i = 0; i < 4; i++) 
		for (j = 0; j < Nb; j++) 
			state[Nb*i+j] = s_box[state[Nb*i+j]];
			// s_box row: yyyy ----
			// s_box col: ---- xxxx
			// s_box[16*(yyyy) + xxxx] == s_box[yyyyxxxx]
			
}

/*Transformation in the Inverse Cipher that is the inverse of SubBytes().*/
void inv_sub_bytes(uint8_t *state) 
{
	uint8_t i, j;

	for (i = 0; i < 4; i++) 
		for (j = 0; j < Nb; j++) 
			state[Nb*i+j] = inv_s_box[state[Nb*i+j]];
}

/*
 * Function used in the Key Expansion routine that takes a four-byte 
 * input word and applies an S-box to each of the four bytes to 
 * produce an output word.
 */
void sub_word(uint8_t *w) 
{
	uint8_t i;
	for (i = 0; i < 4; i++)
		w[i] = s_box[w[i]];
}

/*
 * Function used in the Key Expansion routine that takes a four-byte 
 * word and performs a cyclic permutation. 
 */
void rot_word(uint8_t *w) 
{

	uint8_t tmp;
	uint8_t i;

	tmp = w[0];

	for (i = 0; i < 3; i++)
		w[i] = w[i+1];

	w[3] = tmp;
}

/*Key Expansion*/
void aes_key_expansion(uint8_t *key, uint8_t *w) {

	uint8_t tmp[4];
	uint8_t i;
	uint8_t len = Nb*(Nr+1);

	for (i = 0; i < Nk; i++) 
	{
		w[4*i+0] = key[4*i+0];
		w[4*i+1] = key[4*i+1];
		w[4*i+2] = key[4*i+2];
		w[4*i+3] = key[4*i+3];
	}

	for (i = Nk; i < len; i++) 
	{
		tmp[0] = w[4*(i-1)+0];
		tmp[1] = w[4*(i-1)+1];
		tmp[2] = w[4*(i-1)+2];
		tmp[3] = w[4*(i-1)+3];

		if (i%Nk == 0) 
		{
			rot_word(tmp);
			sub_word(tmp);
			coef_add(tmp, Rcon(i/Nk), tmp);
		} 
		else if (Nk > 6 && i%Nk == 4)
			sub_word(tmp);

		w[4*i+0] = w[4*(i-Nk)+0]^tmp[0];
		w[4*i+1] = w[4*(i-Nk)+1]^tmp[1];
		w[4*i+2] = w[4*(i-Nk)+2]^tmp[2];
		w[4*i+3] = w[4*(i-Nk)+3]^tmp[3];
	}
}


/*Initialize AES variables and allocate memory for expanded key*/
//initialized number of 32 bit words in the cipher key from the key size
//
uint8_t *aes_init(size_t key_size) 
{

        switch (key_size*8) {
		default:
		case 128: Nk = 4; Nr = 10; break;
		case 192: Nk = 6; Nr = 12; break;
		case 256: Nk = 8; Nr = 14; break;
	}

	return malloc(Nb*(Nr+1)*4);
}

/*Performs the AES cipher operation*/
void aes_cipher(uint8_t *in, uint8_t *out, uint8_t *w) 
{

	uint8_t state[4*Nb];
	uint8_t r, i, j;

	for (i = 0; i < 4; i++)
		for (j = 0; j < Nb; j++)
			state[Nb*i+j] = in[i+4*j];

	add_round_key(state, w, 0);

	for (r = 1; r < Nr; r++) 
	{
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, w, r);
	}

	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, w, Nr);

	for (i = 0; i < 4; i++)
		for (j = 0; j < Nb; j++)
			out[i+4*j] = state[Nb*i+j];
}

/*Performs the AES inverse cipher operation*/
void aes_inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w) 
{

	uint8_t state[4*Nb];
	uint8_t r, i, j;

	for (i = 0; i < 4; i++)
		for (j = 0; j < Nb; j++)
			state[Nb*i+j] = in[i+4*j];

	add_round_key(state, w, Nr);

	for (r = Nr-1; r >= 1; r--) 
	{
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, w, r);
		inv_mix_columns(state);
	}

	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, w, 0);

	for (i = 0; i < 4; i++)
		for (j = 0; j < Nb; j++)
			out[i+4*j] = state[Nb*i+j];
}
