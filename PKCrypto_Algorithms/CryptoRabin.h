#pragma once
#include "CryptoBase.h"
#include "Mpz.h"
#include <cstring>
#include <memory>
#include <string>
#include <vector>

class CryptoRabin : public CryptoBase
{
private:
	static constexpr size_t key_factors_max_size = 200;
	gmp::Mpz p, q, n;
	void e_euclid(gmp::Mpz& a, gmp::Mpz& b, gmp::Mpz& gcd_a_b) const;
	void euclid(const gmp::Mpz& a, const gmp::Mpz& b, gmp::Mpz& x, gmp::Mpz& y, gmp::Mpz& d) const;
	inline bool check_plaintext_chars(const std::unique_ptr<char[]>& chars, const int size) const {
		return std::memcmp(chars.get() + size - 12, "11111111111", 11) == 0;
	}
	void calculate_four_candidates(const gmp::Mpz& ciphertext, const gmp::Mpz& a, const gmp::Mpz& b, gmp::Mpz& x, gmp::Mpz& mx_mod_n, gmp::Mpz& y, gmp::Mpz& my_mod_n) const;
	gmp::Mpz get_correct_plaintext(const gmp::Mpz& x, const gmp::Mpz& y, const gmp::Mpz& mx_mod_n, const gmp::Mpz& my_mod_n) const;
public:
	CryptoRabin();
	CryptoRabin(const gmp::Mpz& p, const gmp::Mpz& q);
	~CryptoRabin() = default;
	void print_parameters() const override;
	gmp::Mpz english_to_decimal(const std::string& word) const override;
	bool encrypt(const gmp::Mpz& cleartext, std::vector<gmp::Mpz>& ciphertext) override;
	gmp::Mpz decrypt(const std::vector<gmp::Mpz>& ciphertext) override;
	
};

