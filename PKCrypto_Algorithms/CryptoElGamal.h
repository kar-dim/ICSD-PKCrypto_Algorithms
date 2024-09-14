#pragma once
#include "CryptoBase.h"
#include "Mpz.h"

class CryptoElGamal : public CryptoBase
{
private:
	gmp::Mpz p, g, a, public_key;
public:
	static constexpr size_t key_size = 200;
	CryptoElGamal() = default;
	~CryptoElGamal() = default;
	void initialize_parameters() override;
	void print_parameters() const override;
	bool encrypt(const gmp::Mpz &input, gmp::Mpz &ciphertext1, gmp::Mpz &ciphertext2);
	gmp::Mpz decrypt(const gmp::Mpz &ciphertext1, const gmp::Mpz &ciphertext2) const;
};

