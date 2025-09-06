#pragma once
#include "CryptoBase.h"
#include "Mpz.h"
#include <array>
#include <string>
#include <vector>

class CryptoRabin : public CryptoBase
{
private:
	static constexpr size_t key_factors_max_size = 200;
	static const gmp::Mpz redundancy, redundancy_factor;

	gmp::Mpz a, b, gcd_ab, p, q, n;
	void e_euclid(gmp::Mpz& a, gmp::Mpz& b, gmp::Mpz& gcd_a_b) const;
	void euclid(const gmp::Mpz& a, const gmp::Mpz& b, gmp::Mpz& x, gmp::Mpz& y, gmp::Mpz& d) const;
	void calculate_candidates(const gmp::Mpz& ciphertext, const gmp::Mpz& a, const gmp::Mpz& b, std::array<gmp::Mpz, 4>& candidates) const;
	gmp::Mpz get_correct_plaintext(const std::array<gmp::Mpz, 4>& candidates) const;
public:
	CryptoRabin();
	CryptoRabin(const gmp::Mpz& p, const gmp::Mpz& q);
	~CryptoRabin() = default;
	void print_parameters() const override;
	gmp::Mpz english_to_decimal(const std::string& word) const override;
	bool encrypt(const gmp::Mpz& cleartext, std::vector<gmp::Mpz>& ciphertext) override;
	gmp::Mpz decrypt(const std::vector<gmp::Mpz>& ciphertext) override;
	
};

