#include "../PKCrypto_Algorithms/CryptoBase.h"
#include "../PKCrypto_Algorithms/CryptoElGamal.h"
#include "../PKCrypto_Algorithms/Mpz.h"
#include <gtest/gtest.h>
#include <iostream>
#include <memory>

using namespace gmp;
using std::cout;

class TestFixtureElGamal : public ::testing::Test {
protected:
    std::unique_ptr<CryptoBase> crypto;
    const Mpz plaintext_input_ascii{ "101108103097109097108" };
	const Mpz expected_ciphertext_output[2] = { 
        Mpz("1052772789544382235860844005795479865693153932887382852999755"), 
        Mpz("352381922911315976334440827559600986832987595461615796109178") 
    };

	//Στο ElGamal συγκεκριμένα, το private key (a) παράγεται τυχαία, για να έχουμε ντετερμινιστικά αποτελέσματα
	//θα πρέπει να αρχικοποιήσουμε και το private key με κατι σταθερό
    void SetUp() override {
        const Mpz p("1443181843350333235108757304781045310831020653017767699890061");
        const Mpz a("1250824897082261102203480082498194519738912397975462066562374");
        crypto = std::make_unique<CryptoElGamal>(p, a);
    }
};

//Αρχικοποίηση ElGamal
TEST_F(TestFixtureElGamal, Initialize) {
    const Mpz elgamal_decimal_value = crypto->english_to_decimal("elgamal");
    EXPECT_FALSE(elgamal_decimal_value.is_empty());
    EXPECT_EQ(plaintext_input_ascii, elgamal_decimal_value);
}

//Encryption test, στο ElGamal τα ciphertext είναι δυο.
//το αποτελεσμα της κρυπτογράφησης δεν είναι σταθερό, ακόμα και με σταθερά public/private keys
//μπορύμε να ελέγξουμε αν απλώς πέτυχε η κρυπτογράφηση
TEST_F(TestFixtureElGamal, Encrypt) {
    Mpz ciphertext[2];
    EXPECT_TRUE(crypto->encrypt(plaintext_input_ascii, ciphertext));
	EXPECT_TRUE(!ciphertext[0].is_empty() && !ciphertext[1].is_empty());
}

//Decryption test
TEST_F(TestFixtureElGamal, Decrypt) {
    EXPECT_EQ(plaintext_input_ascii, crypto->decrypt(expected_ciphertext_output));
}

//Decode test
TEST_F(TestFixtureElGamal, Decode) {
    const std::string decoded = CryptoBase::decimal_to_english(plaintext_input_ascii);
    EXPECT_FALSE(decoded.empty());
}
