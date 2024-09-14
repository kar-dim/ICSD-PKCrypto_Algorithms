#pragma once
#include "CryptoBase.h"
#include "Mpz.h"

class CryptoElGamal : public CryptoBase
{
private:
	static constexpr size_t key_max_size = 200;
	gmp::Mpz p, g, a, public_key;
public:
	CryptoElGamal() = default;
	~CryptoElGamal() = default;
	void initialize_parameters() override;
	void print_parameters() const override;
	bool encrypt(const gmp::Mpz &input, gmp::Mpz &ciphertext1, gmp::Mpz &ciphertext2);
	gmp::Mpz decrypt(const gmp::Mpz &ciphertext1, const gmp::Mpz &ciphertext2) const;
};

