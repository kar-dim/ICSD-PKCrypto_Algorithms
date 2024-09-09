﻿#include "CryptoBase.h"
#include "CryptoElGamal.h"
#include "CryptoRabin.h"
#include "CryptoRSA.h"
#include "Mpz.h"
#include <iostream>
#include <string>

using std::cout;
using std::string;

int main(int argc, char** argv) {

    if (argc != 3) {
        cout << "No Crypto method or input text found, exiting";
        return -1;
    }

    const string crypto_method(argv[1]);
    const string input(argv[2]);
    //rsa method
    if (crypto_method.compare("rsa") == 0) {
        CryptoRSA rsa;

        //αρχικοποιηση RSA παραμετρων p,q n και totient (phi)
        rsa.initialize_parameters();
        rsa.print_parameters();

        //private key: (d,n) όπου d βρίσκεται ως: e*d = 1 mod (φ(n)) μεσω του αλγοριθμου του Ευκλειδη
        rsa.e_euclid();
        rsa.print_private_key();

        cout << "Plaintext message = " << input << "\n\n";

        const gmp::Mpz rsa_decimal_value = rsa.english_to_decimal(input);
        if (rsa_decimal_value.isEmpty()) {
            cout << "Failed to encode the word! Can't encrypt\n";
            return -1;
        }
        cout << "Encoded characters = ";
        rsa_decimal_value.Mpz_out_str();
        cout << "\n\n";

        //κρυπτογραφημένο Ciphertext στον RSA είναι το εξής: C = m^e mod n, m=rsa_decimal_value, e=65537
        gmp::Mpz ciphertext;
        rsa.encrypt(rsa_decimal_value, ciphertext);

        cout << "Encrypted Ciphertext = ";
        ciphertext.Mpz_out_str();
        cout << "\n\n";

        //decrypt, m = c^d MOD n, c=ciphertext, d=private key, m=plaintext
        gmp::Mpz plaintext;
        rsa.decrypt(plaintext, ciphertext);

        //εκτύπωση του plaintext, πρέπει να είναι ακριβώς ίδιο με το (encoded) μήνυμα.
        cout << "Decrypted (and encoded) Plaintext = ";
        plaintext.Mpz_out_str();
        cout << "\n\n";

        //η αποκρυπτογράφηση έχει τελειώσει, εδώ γίνεται decode (από αριθμό σε string το μήνυμα)
        string decoded = CryptoBase::decimal_to_english(plaintext, 1024);
        if (decoded.empty()) {
            cout << "Could not decode the number!\n";
            return -1;
        }
        cout << "Decoded plaintext = " << decoded;
        return 0;
    }
    //elgamal method
    if (crypto_method.compare("elgamal") == 0) {
        CryptoElGamal elgamal;

        elgamal.initialize_parameters();
        elgamal.print_parameters();

        cout << "Plaintext message = " << input << "\n\n";

        const gmp::Mpz elgamal_decimal_value = elgamal.english_to_decimal(input);
        if (elgamal_decimal_value.isEmpty()) {
            cout << "Failed to encode the word! Can't encrypt\n";
            return -1;
        }
        cout << "Encoded characters = ";
        elgamal_decimal_value.Mpz_out_str();
        cout << "\n\n";

        //κρυπτογράφηση
        gmp::Mpz c1, c2;
        elgamal.encrypt(elgamal_decimal_value,c1, c2);

        //εκτύπωση των δύο ciphertext
        cout << "Encrypted Ciphertext c1 = ";
        c1.Mpz_out_str();
        cout << "\n\nEncrypted Ciphertext c2 = ";
        c2.Mpz_out_str();
        cout << "\n\n";

        //αποκρυπτογράφηση
        gmp::Mpz decrypted;
        elgamal.decrypt(c1, c2, decrypted);

        //εκτύπωση decrypted
        cout << "Decrypted (and encoded) plaintext = ";
        decrypted.Mpz_out_str();
        cout << "\n\n";

        //η αποκρυπτογράφηση έχει τελειώσει, εδώ απλώς κάνουμε decode (από αριθμό σε string το μήνυμα)
        string decoded = CryptoBase::decimal_to_english(decrypted, 200);
        if (decoded.empty()) {
            cout << "Could not decode the number!\n";
            return -1;
        }
        cout << "Decoded plaintext = " << decoded;
        return 0;
    }

    //rabin cryptosystem
    if (crypto_method.compare("rabin") == 0) {
        CryptoRabin rabin;

        rabin.initialize_parameters();
        rabin.print_parameters();

        cout << "Plaintext message = " << input << "\n\n";
        const gmp::Mpz rabin_decimal_value = rabin.english_to_decimal(input);
        if (rabin_decimal_value.isEmpty()) {
            cout << "Failed to encode the word! Can't encrypt\n";
            return -1;
        }
        cout << "Encoded characters (plus redundancy) = ";
        rabin_decimal_value.Mpz_out_str();
        cout << "\n\n";

        //κρυπτογράφηση
        gmp::Mpz ciphertext;
        rabin.encrypt(rabin_decimal_value, ciphertext);
        cout << "Encrypted Ciphertext = ";
        ciphertext.Mpz_out_str();
        cout << "\n\n";

        //decrypt
        //υπολογίζουμε τα a,b επεκταμένο αλγόριθμο του ευκλείδη
        gmp::Mpz a, b, gcd_a_b;
        rabin.e_euclid(a, b, gcd_a_b);

        //εκτύπωση των a,b και του gcd(a,b)=1
        cout << "a = ";
        a.Mpz_out_str();
        cout << "\n\nb = ";
        b.Mpz_out_str();
        cout << "\n\nd (MUST BE 1) = ";
        gcd_a_b.Mpz_out_str();
        cout << "\n\n";
        //αν gcd(a,b) δεν είναι 1 τότε σφάλμα
        if (gcd_a_b.Mpz_cmp_ui(1) != 0) {
            cout << "Error trying to initialize the decryption process! Exiting...";
            return -1;
        }

        //ευρεση των 4 πιθανων plaintexts
        gmp::Mpz x, y, mx_mod_n, my_mod_n;
        //υπολογίζουμε τα r,s,x,y
        rabin.calculate_four_candidates(ciphertext, a, b, x, mx_mod_n, y, my_mod_n);

        //εκτυπώνουμε τα 4 πιθανά plaintext (encoded). Ένα μόνο από αυτά είναι το σωστό
        cout << "1) x = ";
        x.Mpz_out_str();
        cout << "\n\n2) y = ";
        y.Mpz_out_str();
        cout << "\n\n3) -x MOD n = ";
        mx_mod_n.Mpz_out_str();
        cout << "\n\n4) -y MOD n = ";
        my_mod_n.Mpz_out_str();
        cout << "\n\n";

        //τώρα πρέπει να βρούμε ποιό από τα 4 είναι το σωστό
        gmp::Mpz correct_plaintext = rabin.get_correct_plaintext(x, y, mx_mod_n, my_mod_n);
        if (correct_plaintext.isEmpty()) {
            cout << "Could not decrypt, none of the plaintext are correct";
            return -1;
        }
        //decode το plaintext
        string decoded = CryptoBase::decimal_to_english(correct_plaintext, 1024);
        if (decoded.empty()) {
            cout << "Could not decode the number!\n";
            return -1;
        }
        cout << "Decrypted and decoded (no redundancy) plaintext = " << decoded;
        return 0;
    }

    else {
        cout << "Wrong crypto method. Only 'rsa','elgamal' and 'rabin' allowed";
        return -1;
    }
}

