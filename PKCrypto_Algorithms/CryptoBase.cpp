#include "CryptoBase.h"
#include "Mpz.h"
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <format>
#include <memory>
#include <string>

using std::string;

CryptoBase::CryptoBase() {
    gmp_randinit_default(state); //αρχικοποίηση του random state
    gmp_randseed_ui(state, static_cast<ulong>(time(NULL)));
}

CryptoBase::~CryptoBase() {
    gmp_randclear(state);
}

int CryptoBase::number_of_digits(const int n) {
    if (n < 0) return -1;
    int remainder = n;
    int count = 0;
    //μετράμε πόσες φορές γίνεται η διαίρεση με το 10
    while (remainder != 0) {
        remainder /= 10;
        ++count;
    }
    return count;
}

//συνάρτηση για να βρούμε το n-οστό ψηφίο ενός αριθμού
int CryptoBase::get_digit(const int num, const int n) {
    int result = num % static_cast<int>(std::pow(10, n + 1));
    //αν δε θέλουμε το τελευταίο ψηφίο χρειάζεται ακόμα μια διαίρεση
    if (n > 0) {
        result /= static_cast<int>(std::pow<int>(10, n));
    }
    return result;
}

string CryptoBase::english_to_decimal_str(const string& word) const {
    string characters_as_numbers; //ένας τριψήφιος αριθμός είναι ένα γράμμα στο ASCII (pad με 0 μπροστά αν είναι διψήφιος)
    for (auto i = 0; i < word.length(); i++) {
        //παίρνουμε τη ASCII μορφή του χαρακτήρα
        const int ascii_value = static_cast<int>(word[i]);
        const int num_of_digits = CryptoBase::number_of_digits(ascii_value);
        if (num_of_digits <= 1 || num_of_digits > 3)
            return "";
        //αν είναι 2ψήφιος τότε βάζουμε ένα 0 μπροστά
        characters_as_numbers += std::format("{:03}", ascii_value);
    }
    return characters_as_numbers;
}

//συναρτήση για τη κωδικοποίηση ενός αριθμού ως μια λέξη (ASCII)
gmp::Mpz CryptoBase::english_to_decimal(const string &word) const {
    gmp::Mpz number;
    string characters_as_numbers = CryptoBase::english_to_decimal_str(word);
    if (characters_as_numbers.empty())
        return number;
    //store σε GNU MP array
    number.Mpz_set_str(characters_as_numbers.c_str());
    return number;
}

string CryptoBase::decimal_to_english(gmp::Mpz& number, const int max_bytes) {
    std::unique_ptr<char[]> number_buff(new char[max_bytes]);//200 για elgamal, 1024 για rabin/rsa
    int size = gmp_sprintf(number_buff.get(), "%Zd", number);

    //pad με 0 αν το πρωτο γραμμα ειναι 'α', 'b' ή 'c' πχ "97" (α) -> "097"
    if (number_buff[0] == '9' && (number_buff[1] == '7' || number_buff[1] == '8' || number_buff[1] == '9')) {
        std::memcpy(number_buff.get() + 1, number_buff.get(), size);
        number_buff[0] = '0';
        number_buff[++size] = '\0';
    }
        
    string decoded_output;
    char temp_buf[4] = { 0 };
    for (int i = 0; i < size / 3; i++) {
        std::memcpy(temp_buf, &number_buff[i * 3], 3);
        decoded_output += std::atoi(temp_buf);
    }
    return decoded_output;
}

