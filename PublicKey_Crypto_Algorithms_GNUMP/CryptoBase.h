#pragma once

#include<gmp.h>
#include <string>
#include "Mpz.h"

class CryptoBase
{
protected:
    gmp_randstate_t state; //random state χρειάζεται για να δουλέψουν οι αλγόριθμοι παραγωγής τυχαίων
	static int number_of_digits(int n);
	//συνάρτηση για εύρεση του n-οστου ψηφίου ενός αριθμού ξεκινοντας άπό το λιγότερο σήμαντικό ψηφίο
	static int get_digit(int num, int n);
public:
	CryptoBase();
	~CryptoBase();
	virtual void initialize_parameters() = 0;
	virtual void print_parameters() = 0;
	virtual bool english_to_decimal(gmp::Mpz& number, const std::string& word);
	bool decimal_to_english(gmp::Mpz &number, std::string& final_chars, int max_bits);
};

