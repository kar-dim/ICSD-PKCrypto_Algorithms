﻿#pragma once
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
	CryptoRSA(const gmp::Mpz& p, const gmp::Mpz& q);
	~CryptoRSA() = default;
	void print_parameters() const override;
	bool encrypt(const gmp::Mpz& cleartext, gmp::Mpz ciphertexts[]) override;
	gmp::Mpz decrypt(const gmp::Mpz ciphertexts[]) override;
};

