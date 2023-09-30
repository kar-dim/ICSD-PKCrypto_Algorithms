#pragma once
#include "CryptoBase.h"
#include <string>
class CryptoRabin : public CryptoBase
{
private:
	gmp::Mpz p, q, n;
	void euclid(gmp::Mpz& a, gmp::Mpz& b, gmp::Mpz& x, gmp::Mpz& y, gmp::Mpz& d);
public:
	CryptoRabin() = default;
	~CryptoRabin() = default;
	void print_parameters() override;
	void e_euclid(gmp::Mpz &a, gmp::Mpz &b, gmp::Mpz &gcd_a_b);
	void initialize_parameters() override;
	bool english_to_decimal(gmp::Mpz &number, const std::string& word) override;
	void encrypt(const gmp::Mpz &cleartext, gmp::Mpz &ciphertext);
	void calculate_four_candidates(const gmp::Mpz &ciphertext, const gmp::Mpz& a, const gmp::Mpz &b, gmp::Mpz& x, gmp::Mpz& mx_mod_n, gmp::Mpz& y, gmp::Mpz& my_mod_n);
	bool get_correct_plaintext(const gmp::Mpz& x, const gmp::Mpz& y, const gmp::Mpz& mx_mod_n, const gmp::Mpz& my_mod_n, gmp::Mpz& correct_plaintext);
};

