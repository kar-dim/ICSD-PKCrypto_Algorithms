#pragma once
#include "CryptoBase.h"
#include "Mpz.h"

class CryptoElGamal : public CryptoBase
{
private:
	static constexpr size_t key_max_size = 200;
	gmp::Mpz p, g, a, public_key;
public:
	CryptoElGamal();
	CryptoElGamal(const gmp::Mpz& p, const gmp::Mpz& a);
	~CryptoElGamal() = default;
	void print_parameters() const override;
	bool encrypt(const gmp::Mpz& cleartext, gmp::Mpz ciphertexts[]) override;
	gmp::Mpz decrypt(const gmp::Mpz ciphertexts[]) override;
};

