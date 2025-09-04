#pragma once

#include "Mpz.h"
#include <gmp.h>
#include <string>
#include <vector>

class CryptoBase
{
protected:
    gmp_randstate_t state; //random state χρειάζεται για να δουλέψουν οι αλγόριθμοι παραγωγής τυχαίων
	size_t public_key_size;
public:
	CryptoBase();
	virtual ~CryptoBase();
	virtual void print_parameters() const = 0;
	virtual gmp::Mpz english_to_decimal(const std::string& word) const;
	size_t get_public_key_size() const;
	static std::string decimal_to_english(const gmp::Mpz &number);
	virtual bool encrypt(const gmp::Mpz& cleartext, std::vector<gmp::Mpz>& ciphertext) = 0;
	virtual gmp::Mpz decrypt(const std::vector<gmp::Mpz>& ciphertext) = 0;
};

