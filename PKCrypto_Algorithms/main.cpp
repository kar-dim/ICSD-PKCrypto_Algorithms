#include "CryptoBase.h"
#include "CryptoElGamal.h"
#include "CryptoRabin.h"
#include "CryptoRSA.h"
#include "Mpz.h"
#include <iostream>
#include <string>
#include <memory>

using std::cout;
using std::string;
using gmp::Mpz;

int main(int argc, char** argv) {
    if (argc != 3) {
        cout << "No Crypto method or input text found, exiting";
        return -1;
    }
    const string crypto_method(argv[1]);
    const string input(argv[2]);
    std::unique_ptr<CryptoBase> crypto;
    //rsa method
    if (crypto_method.compare("rsa") == 0) {
        crypto = std::make_unique<CryptoRSA>();
        crypto->print_parameters();

        cout << "Plaintext message = " << input << "\n\n";
        const Mpz rsa_decimal_value = crypto->english_to_decimal(input);
        if (rsa_decimal_value.is_empty()) {
            cout << "Failed to encode the word! Can't encrypt\n";
            return -1;
        }
        cout << "Encoded characters = " << rsa_decimal_value << "\n\n";

        //κρυπτογραφημένο Ciphertext στον RSA είναι το εξής: C = m^e mod n, m=rsa_decimal_value, e=65537
        Mpz ciphertext[1];
        if (!crypto->encrypt(rsa_decimal_value, ciphertext)) {
            cout << "Failed to encrypt! Maximum allowed input size is: " << crypto->get_public_key_size() - 1 << " bits, input size is: " << rsa_decimal_value.size_in_bits() << " bits\n";
            return -1;
        }
        cout << "Encrypted Ciphertext = " << ciphertext[0] << "\n\n";

        //decrypt, m = c^d MOD n, c=ciphertext, d=private key, m=plaintext
        const Mpz plaintext = crypto->decrypt(ciphertext);
        
        //εκτύπωση του plaintext, πρέπει να είναι ακριβώς ίδιο με το (encoded) μήνυμα.
        cout << "Decrypted (and encoded) Plaintext = " << plaintext << "\n\n";
        //η αποκρυπτογράφηση έχει τελειώσει, εδώ γίνεται decode (από αριθμό σε string το μήνυμα)
        const string decoded = CryptoBase::decimal_to_english(plaintext);
        if (decoded.empty()) {
            cout << "Could not decode the number!\n";
            return -1;
        }
        cout << "Decoded plaintext = " << decoded;
        return 0;
    }
    //elgamal method
    if (crypto_method.compare("elgamal") == 0) {
        crypto = std::make_unique<CryptoElGamal>();
        crypto->print_parameters();
        cout << "Plaintext message = " << input << "\n\n";

        const Mpz elgamal_decimal_value = crypto->english_to_decimal(input);
        if (elgamal_decimal_value.is_empty()) {
            cout << "Failed to encode the word! Can't encrypt\n";
            return -1;
        }
        cout << "Encoded characters = " << elgamal_decimal_value << "\n\n";

        //κρυπτογράφηση
        Mpz ciphertexts[2];
        if (!crypto->encrypt(elgamal_decimal_value, ciphertexts)) {
            cout << "Failed to encrypt! Maximum allowed input size is: " << crypto->get_public_key_size() - 1 << " bits, input size is: " << elgamal_decimal_value.size_in_bits() << " bits\n";
            return -1;
        }
        //εκτύπωση των δύο ciphertext
        cout << "Encrypted Ciphertext c1 = " << ciphertexts[0] << "\n\n";
        cout << "Encrypted Ciphertext c2 = " << ciphertexts[1] << "\n\n";

        //αποκρυπτογράφηση
        const Mpz decrypted = crypto->decrypt(ciphertexts);
        //εκτύπωση decrypted
        cout << "Decrypted (and encoded) plaintext = " << decrypted << "\n\n";
        //η αποκρυπτογράφηση έχει τελειώσει, εδώ απλώς κάνουμε decode (από αριθμό σε string το μήνυμα)
        const string decoded = CryptoBase::decimal_to_english(decrypted);
        if (decoded.empty()) {
            cout << "Could not decode the number!\n";
            return -1;
        }
        cout << "Decoded plaintext = " << decoded;
        return 0;
    }

    //rabin cryptosystem
    if (crypto_method.compare("rabin") == 0) {
        crypto = std::make_unique<CryptoRabin>();
        crypto->print_parameters();

        cout << "Plaintext message = " << input << "\n\n";
        const Mpz rabin_decimal_value = crypto->english_to_decimal(input);
        if (rabin_decimal_value.is_empty()) {
            cout << "Failed to encode the word! Can't encrypt\n";
            return -1;
        }
        cout << "Encoded characters (plus redundancy) = " << rabin_decimal_value << "\n\n";

        //κρυπτογράφηση
        Mpz ciphertext[1];
        if (!crypto->encrypt(rabin_decimal_value, ciphertext)) {
            cout << "Failed to encrypt! Maximum allowed input size is: " << crypto->get_public_key_size() - 1 << " bits, input size is: " << rabin_decimal_value.size_in_bits() << " bits\n";
            return -1;
        }
        cout << "Encrypted Ciphertext = " << ciphertext[0] << "\n\n";

        //decrypt
        //υπολογίζουμε τα a,b επεκταμένο αλγόριθμο του ευκλείδη
        const Mpz plaintext = crypto->decrypt(ciphertext);
        if (plaintext.is_empty()) {
            cout << "Could not decrypt, error in initialization process or none of the plaintext are correct";
            return -1;
        }
        //decode το plaintext
        const string decoded = CryptoBase::decimal_to_english(plaintext);
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

