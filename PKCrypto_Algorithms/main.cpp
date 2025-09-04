#include "CryptoBase.h"
#include "CryptoElGamal.h"
#include "CryptoRabin.h"
#include "CryptoRSA.h"
#include "Mpz.h"
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using std::cout;
using std::string;
using gmp::Mpz;

static int encode(const std::unique_ptr<CryptoBase>& crypto, const string& input, Mpz& decimal_value) {
    cout << "Plaintext message = " << input << "\n\n";
    decimal_value = crypto->english_to_decimal(input);
    if (decimal_value.is_empty()) {
        cout << "Failed to encode the word! Can't encrypt\n";
        return -1;
    }
    cout << "Encoded characters = " << decimal_value << "\n\n";
    return 0;
}

static int encrypt(const std::unique_ptr<CryptoBase>& crypto, const Mpz& decimal_value, std::vector<Mpz>& ciphertext) {
    if (!crypto->encrypt(decimal_value, ciphertext)) {
        cout << "Failed to encrypt! Maximum allowed input size is: " << crypto->get_public_key_size() - 1 << " bits, input size is: " << decimal_value.size_in_bits() << " bits\n";
        return -1;
    }
	for (const auto &cipher : ciphertext)
        cout << "Encrypted Ciphertext = " << cipher << "\n\n";
    return 0;
}

static int decrypt(std::unique_ptr<CryptoBase>& crypto, const std::vector<Mpz>& ciphertext, Mpz& decrypted, string& decoded) {
    decrypted = crypto->decrypt(ciphertext);
    if (decrypted.is_empty()) {
        cout << "Could not decrypt!";
        return -1;
    }
    cout << "Decrypted (and encoded) plaintext = " << decrypted << "\n\n";
    decoded = CryptoBase::decimal_to_english(decrypted);
    if (decoded.empty()) {
        cout << "Could not decode the number!\n";
        return -1;
    }
    cout << "Decoded plaintext = " << decoded;
    return 0;
}

static int process(std::unique_ptr<CryptoBase>& crypto, const string& input, std::vector<Mpz>& ciphertext) {
    crypto->print_parameters();
    //encode
    Mpz decimal_value;
    if (encode(crypto, input, decimal_value) != 0)
        return -1;
    //encrypt
    if (encrypt(crypto, decimal_value, ciphertext) != 0)
        return -1;
    //decrypt
    Mpz decrypted;
    string decoded;
    if (decrypt(crypto, ciphertext, decrypted, decoded) != 0)
        return -1;
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        cout << "No Crypto method or input text found, exiting";
        return -1;
    }
    const string crypto_method(argv[1]);
    const string input(argv[2]);
	std::vector<Mpz> ciphertext(1);
    std::unique_ptr<CryptoBase> crypto;
    if (crypto_method.compare("rsa") == 0)
        crypto = std::make_unique<CryptoRSA>();
    else if (crypto_method.compare("elgamal") == 0) {
        crypto = std::make_unique<CryptoElGamal>();
		ciphertext.resize(2); //elgamal has 2 ciphertext numbers
    }
    else if (crypto_method.compare("rabin") == 0)
        crypto = std::make_unique<CryptoRabin>();
    else {
        cout << "Wrong crypto method. Only 'rsa','elgamal' and 'rabin' allowed";
        return -1;
    }
    return process(crypto, input, ciphertext);
}

