#include "CryptoBase.h"
#include <memory>
#include <string>
#include <iostream>

using std::cout;

void CryptoBase::init() {
    static bool isInitialized = false;
    if (isInitialized == false) {
        gmp_randinit_default(state); //αρχικοποίηση του random state
        gmp_randseed_ui(state, static_cast<unsigned long>(time(NULL)));
        isInitialized = true;
    }
}

int CryptoBase::number_of_digits(int n) {
    if (n < 0) return -1;
    int count = 0;
    //μετράμε πόσες φορές γίνεται η διαίρεση με το 10
    while (n != 0) {
        n = n / 10;
        ++count;
    }
    return count;
}

//συνάρτηση για να βρούμε το n-οστό ψηφίο ενός αριθμού
int CryptoBase::get_digit(int num, int n) {
    int result, res1, res2;
    //res1 = 10^4 = 10000
    res1 = (int)pow(10, n + 1);
    //r = 5721 % 10000 -> r=5721
    result = num % res1;

    //αν δε θέλουμε το τελευταίο ψηφίο χρειάζεται ακόμα μια διαίρεση
    if (n > 0) {
        //res2 = 10^3 = 1000
        res2 = (int)pow(10, n);
        //r = 5721 / 1000 = 5
        result = result / res2;
    }

    return result;
}
//συναρτήση για τη κωδικοποίηση ενός αριθμού ως μια λέξη (ASCII)
bool CryptoBase::english_to_decimal(mpz_t number, const std::string &word) {
    int size = (int)word.length();
    std::string characters_as_numbers = ""; //ένας τριψήφιος αριθμός είναι ένα γράμμα στο ASCII (pad με 0 μπροστά αν είναι διψήφιος)
    for (int i = 0; i < size; i++) {
        //παίρνουμε τη ASCII μορφή του χαρακτήρα
        int temp = (int)word[i];
        int num_of_digits = CryptoBase::number_of_digits(temp);
        if (num_of_digits <= 1 || num_of_digits > 3) {
            cout << "Not an English word, can't encrypt it!\n";
            return false;
        }
        //αν είναι 2ψήφιος τότε βάζουμε ένα 0 μπροστά
        characters_as_numbers += num_of_digits == 2 ? '0' : (get_digit(temp, 2) + '0');
        characters_as_numbers += (get_digit(temp, 1) + '0');
        characters_as_numbers += (get_digit(temp, 0) + '0');
    }
    cout << "Encoded characters: " << characters_as_numbers << "\n\n";
    //store σε GNU MP array
    mpz_init(number);
    if (mpz_set_str(number, characters_as_numbers.c_str(), 10) == -1) {
        cout << "Failed to encode the word! Can't encrypt\n";
        return false;
    }
    return true;
}

bool CryptoBase::decimal_to_english(mpz_t number, std::string &final_chars, int max_bits) {
    std::unique_ptr<char[]> temp(new char[max_bits]);//200 για elgamal, 1024 για rabin/rsa
    int size = gmp_sprintf(temp.get(), "%Zd", number);
    //size είναι ο αριθμός των χαρακτήρων που διαβάστηκαν, αν δε διαβάστηκε τίποτα τότε σφάλμα
    if (size < 1) {
        cout << "Could not read the number!\n";
        return false;
    }
    char temp_buf[4] = { 0 };
    for (int i = 0; i < size / 3; i++) {
        memcpy(temp_buf, &temp[i * 3], 3);
        final_chars += atoi(temp_buf);
    }
    return true;
}

