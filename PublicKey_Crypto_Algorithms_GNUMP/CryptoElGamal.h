#pragma once
#include "CryptoBase.h"
class CryptoElGamal : public CryptoBase
{
private:
	mpz_t p, g, a, public_key;
public:
	void init() override;
	void initialize_parameters() override;
	void print_parameters() override;
	void encrypt(mpz_t input, mpz_t ciphertext1, mpz_t ciphertext2);
	void decrypt(mpz_t ciphertext1, mpz_t ciphertext2, mpz_t output_plaintext);
};

