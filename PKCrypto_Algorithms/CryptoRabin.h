#pragma once
#include "CryptoBase.h"
#include "Mpz.h"
#include <memory>
#include <string>

class CryptoRabin : public CryptoBase
{
private:
	static constexpr size_t key_factors_max_size = 200;
	gmp::Mpz p, q, n;
	void euclid(gmp::Mpz& a, gmp::Mpz& b, gmp::Mpz& x, gmp::Mpz& y, gmp::Mpz& d) const;
	void check_and_retrieve_plaintext(const bool is_correct, const std::unique_ptr<char[]>& chars, const size_t size, std::string& buf) const;
	bool check_plaintext_chars(const std::unique_ptr<char[]>& chars, const int size) const;
public:
	
	CryptoRabin();
	~CryptoRabin() = default;
	void print_parameters() const override;
	void e_euclid(gmp::Mpz &a, gmp::Mpz &b, gmp::Mpz &gcd_a_b);
	gmp::Mpz english_to_decimal(const std::string& word) const override;
	bool encrypt(const gmp::Mpz &cleartext, gmp::Mpz &ciphertext) const;
	void calculate_four_candidates(const gmp::Mpz &ciphertext, const gmp::Mpz& a, const gmp::Mpz &b, gmp::Mpz& x, gmp::Mpz& mx_mod_n, gmp::Mpz& y, gmp::Mpz& my_mod_n) const;
	gmp::Mpz get_correct_plaintext(const gmp::Mpz& x, const gmp::Mpz& y, const gmp::Mpz& mx_mod_n, const gmp::Mpz& my_mod_n) const;
};

