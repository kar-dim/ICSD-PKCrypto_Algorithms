#pragma once
#include "CryptoBase.h"
class CryptoRabin : public CryptoBase
{
private:
	mpz_t p, q, n;
	void euclid(mpz_t a, mpz_t b, mpz_t x, mpz_t y, mpz_t d);
public:
	void init() override;
	void print_parameters() override;
	void e_euclid(mpz_t a, mpz_t b, mpz_t gcd_a_b);
	void initialize_parameters() override;
	bool english_to_decimal(mpz_t number, const char* word) override;
	void encrypt(mpz_t cleartext, mpz_t ciphertext);
	void calculate_four_candidates(mpz_t ciphertext, mpz_t a, mpz_t b, mpz_t x, mpz_t mx_mod_n, mpz_t y, mpz_t my_mod_n);
	bool get_correct_plaintext(mpz_t x, mpz_t y, mpz_t mx_mod_n, mpz_t my_mod_n, mpz_t correct_plaintext);
};

