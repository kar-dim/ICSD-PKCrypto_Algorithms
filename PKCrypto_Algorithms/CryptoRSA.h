#pragma once
#include "CryptoBase.h"
#include "Mpz.h"

class CryptoRSA : public CryptoBase
{
private:
	gmp::Mpz p, q, n, e, d, totient;
public:
	CryptoRSA();
	~CryptoRSA() = default;
	//υπολογισμος των p,q,n + υπολογισμός του φ(n) = φ(p)φ(q) = (p-1)(q-1), λόγω ότι p,q είναι primes
	void initialize_parameters() override;
	//εκτυπωση
	void print_parameters() const override;
	void print_private_key() const;

	//συνάρτηση του επεκταμένου αλγορίθμου του Ευκλείδη (αντίστροφο του a mod m, δηλαδή a*p1 == 1(mod m) -> a*p1 = km + 1)
	void e_euclid();

	void encrypt(const gmp::Mpz &input, gmp::Mpz &output) const;
	void decrypt(gmp::Mpz &output, const gmp::Mpz &input) const;
};

