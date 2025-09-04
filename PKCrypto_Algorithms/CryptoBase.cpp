#include "CryptoBase.h"
#include "Mpz.h"
#include <algorithm>
#include <ctime>
#include <gmp.h>
#include <string>

using std::string;
using gmp::Mpz;

CryptoBase::CryptoBase() {
    public_key_size = 0;
    gmp_randinit_default(state); //αρχικοποίηση του random state
    gmp_randseed_ui(state, static_cast<ulong>(time(NULL)));
}

CryptoBase::~CryptoBase() {
    gmp_randclear(state);
}

//συναρτήση για τη κωδικοποίηση ενός αριθμού ως μια λέξη (Base-256)
Mpz CryptoBase::english_to_decimal(const string &word) const {
    Mpz number(0);
    for (unsigned char c : word) {
        number *= 256;
        number += c;
    }
    return number;
}

size_t CryptoBase::get_public_key_size() const
{
    return public_key_size;
}

//συναρτήση για τη αποκωδικοποίηση ενός αριθμού ως μια λέξη (Base-256)
string CryptoBase::decimal_to_english(const Mpz& number) {
    Mpz n = number;
    std::string result;
    while (n > 0) {
        result += static_cast<unsigned char>(Mpz::get_ui(n % 256));
        n /= 256;
    }
    std::reverse(result.begin(), result.end());
    return result;
}

