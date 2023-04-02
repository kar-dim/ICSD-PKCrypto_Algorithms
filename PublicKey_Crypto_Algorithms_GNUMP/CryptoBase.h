#pragma once

#include<gmp.h>
#include <string>

class CryptoBase
{
protected:
    gmp_randstate_t state; //random state χρειάζεται για να δουλέψουν οι αλγόριθμοι παραγωγής τυχαίων της βιβλιοθήκης
	//απλή συνάρτηση για να μετρήσουμε το πλήθος των ψηφίων, πχ 43 -> 2, 128 =3 κτλ
	static int number_of_digits(int n);

	//απλή συνάρτηση για να βρούμε το n-οστό ψηφίο ενός αριθμού (πχ 982,2 θα επιστρέψει το 9)
	//n ξεκινάει από 0 και τέλος μετράμε από το πιο ασήμαντο ψηφίο (άρα 4012, 3 εννοούμε το 4)
	static int get_digit(int num, int n);
public:
    virtual void init();
	virtual void initialize_parameters() = 0;
	virtual void print_parameters() = 0;
	virtual bool english_to_decimal(mpz_t number, const std::string& word);
	bool decimal_to_english(mpz_t number, std::string& final_chars, int max_bits);
};

