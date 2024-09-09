#pragma once

#include "Mpz.h"
#include <gmp.h>
#include <string>

class CryptoBase
{
protected:
    gmp_randstate_t state; //random state χρειάζεται για να δουλέψουν οι αλγόριθμοι παραγωγής τυχαίων
	static int number_of_digits(const int n);
	//συνάρτηση για εύρεση του n-οστου ψηφίου ενός αριθμού ξεκινοντας άπό το λιγότερο σήμαντικό ψηφίο
	static int get_digit(const int num, const int n);
	std::string english_to_decimal_str(const std::string& word) const;
public:
	CryptoBase();
	virtual ~CryptoBase();
	virtual void initialize_parameters() = 0;
	virtual void print_parameters() const = 0;
	virtual gmp::Mpz english_to_decimal(const std::string& word) const;
	static std::string decimal_to_english(gmp::Mpz &number, const int max_bits);
};

