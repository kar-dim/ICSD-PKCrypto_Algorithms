﻿#pragma once
#include "CryptoBase.h"
#include "Mpz.h"

class CryptoRSA : public CryptoBase
{
private:
	static constexpr int e_value = 65537;
	static constexpr size_t key_factors_max_size = 512;
	gmp::Mpz p, q, n, e, d, totient;
public:
	CryptoRSA();
	~CryptoRSA() = default;
	//υπολογισμος των p,q,n + υπολογισμός του φ(n) = φ(p)φ(q) = (p-1)(q-1), λόγω ότι p,q είναι primes
	void initialize_parameters() override;
	//εκτυπωση
	void print_parameters() const override;

	//συνάρτηση του επεκταμένου αλγορίθμου του Ευκλείδη (αντίστροφο του a mod m, δηλαδή a*p1 == 1(mod m) -> a*p1 = km + 1)
	bool e_euclid();

	bool encrypt(const gmp::Mpz &input, gmp::Mpz &output) const;
	gmp::Mpz decrypt(const gmp::Mpz &input) const;
};

