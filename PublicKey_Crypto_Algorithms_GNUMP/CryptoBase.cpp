#include "CryptoBase.h"
#include <memory>
#include <string>
#include <iostream>

using std::cout;

void CryptoBase::init() {
    static bool isInitialized = false;
    if (isInitialized == false) {
        gmp_randinit_default(state); //αρχικοποίηση του random state
        gmp_randseed_ui(state, static_cast<unsigned long>(time(NULL))); //random seed
        isInitialized = true;
    }
}

int CryptoBase::number_of_digits(int n) {
    if (n < 0) return -1;
    int count = 0;
    //απλώς μετράμε πόσες φορές γίνεται η διαίρεση με το 10 (άρα το 668 -> 66 -> 6 -> 0, 3 ψηφία)
    while (n != 0) {
        n = n / 10;
        ++count;
    }
    return count;
}

//απλή συνάρτηση για να βρούμε το n-οστό ψηφίο ενός αριθμού (πχ 982,2 θα επιστρέψει το 9)
//n ξεκινάει από 0 και τέλος μετράμε από το πιο ασήμαντο ψηφίο (άρα 4012, 3 εννοούμε το 4)

int CryptoBase::get_digit(int num, int n) {
    //πχ για num=5721, n=3 (θα βγάλει το 5)
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
//δύο συναρτήσεις για τη κωδικοποίηση ενός αριθμού ως μια λέξη
//και το αντίστροφο. Έκανα τη πιο απλή περίπτωση (η οποία δεν είναι ασφαλής, χωρίς padding ή εφαρμογή ΟAEP κτλ)
//συγκεκριμένα η μετατροπή χρησιμοποιεί τον πίνακα ASCII. Άρα το 'rsa' στο δεκαδικό είναι το '114115097' αφου r=114, s=115, a=97
//στο ASCII (βαζουμε 0 για να έχουμε ίδιο αριθμό ψηφίων, οπότε κάθε 3 δεκαδικοί αριθμοί είναι ένα γράμμα)
//ή Rabin class την κάνει override διοτι έχει διαφορές στη μετατροπή (ειναι η ιδια υλοποίηση για RSA/ElGamal)
bool CryptoBase::english_to_decimal(mpz_t number, const std::string &word) {
    int size = (int)word.length();
    std::string characters_as_numbers = ""; //ένας τριψήφιος αριθμός είναι ένα γράμμα στο ASCII (pad με 0 μπροστά αν είναι διψήφιος)
    for (int i = 0; i < size; i++) {
        //παίρνουμε τη ASCII μορφή του χαρακτήρα
        int temp = (int)word[i];
        //αν είναι 2ψήφιος τότε βάζουμε ένα 0 μπροστά
        if (CryptoBase::number_of_digits(temp) == 2) {
            characters_as_numbers += '0';
            characters_as_numbers += (get_digit(temp, 1) + '0');
            characters_as_numbers += (get_digit(temp, 0) + '0');
        }
        else if (number_of_digits(temp) == 3) {
            characters_as_numbers += (get_digit(temp, 2) + '0');
            characters_as_numbers += (get_digit(temp, 1) + '0');
            characters_as_numbers += (get_digit(temp, 0) + '0');
        }
        else {
            cout << "Not an English word, can't encrypt it!\n";
            return false;
        }
    }
    cout << "Encoded characters: " << characters_as_numbers << "\n\n";
    //τώρα ο πίνακας characters_as_numbers περιέχει τους χαρακτήρες. Άρα για word='rsa' -> 114115097 οπότε αυτός ο αριθμός
    //είναι που θα γίνει (στη συνέχεια) η κρυπτογράφηση, οπότε τον αποθηκεύουμε με το GNUMP
    if (mpz_set_str(number, characters_as_numbers.c_str(), 10) == -1) {
        cout << "Failed to encode the word! Can't encrypt\n";
        return false;
    }
    //αν δεν έχουμε φύγει από τη συνάρτηση σημαίνει πως όλα πήγαν καλά
    //οπότε ο mpz_t number έχει τη τιμή που θέλουμε
    return true;
}

void CryptoBase::decimal_to_english(mpz_t number, std::string &final_chars, int max_bits) {
    //για να μετατρέψουμε τον αριθμό σε string θα γεμίσουμε έναν πίνακα χαρακτήρων πρώτα
    std::unique_ptr<char[]> temp(new char[max_bits]);//200 για elgamal, 1024 για rabin/rsa
    int size = gmp_sprintf(temp.get(), "%Zd", number);
    //size είναι ο αριθμός των χαρακτήρων που διαβάστηκαν, αν δε διαβάστηκε τίποτα τότε σφάλμα
    if (size < 1) {
        cout << "Could not read the number!\n";
        exit(-1);
        return;
    }
    std::string chars(temp.get()); //chars: αριθμοί σε μορφή characters (πχ '113115097')
    //chars είναι ο αριθμός αλλά σε char array μορφή, άρα τους διαβάζουμε τρεις μαζί και μετατρέπουμε τον int σε char
    char temp_buf[3];
    int j = 0;
    for (int i = 0; i < size / 3; i++) {
        temp_buf[0] = chars[i * 3];
        temp_buf[1] = chars[(i * 3) + 1];
        temp_buf[2] = chars[(i * 3) + 2];
        //temp τώρα έχει 3 αριθμούς ως χαρακτήρες, πχ το '097' θα το κάνουμε 'a'
        final_chars += atoi(temp_buf); //atoi: int σε char (decoded τιμες, πχ "rsa")
        j++;
    }
}

