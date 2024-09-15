#pragma once
#include "CryptoBase.h"
#include "Mpz.h"

class CryptoRSA : public CryptoBase
{
private:
	static constexpr int e_value = 65537;
	static constexpr size_t key_factors_max_size = 512;
	gmp::Mpz p, q, n, e, d, totient;
	bool e_euclid();
public:
	CryptoRSA();
	~CryptoRSA() = default;
	void print_parameters() const override;
	bool encrypt(const gmp::Mpz &input, gmp::Mpz &output) const;
	gmp::Mpz decrypt(const gmp::Mpz &ciphertext) const;
};

