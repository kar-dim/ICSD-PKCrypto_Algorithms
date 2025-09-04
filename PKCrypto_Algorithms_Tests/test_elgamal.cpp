#include "CryptoBase.h"
#include "CryptoElGamal.h"
#include "Mpz.h"
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <vector>

using namespace gmp;
using std::cout;

class TestFixtureElGamal : public ::testing::Test {
protected:
    std::unique_ptr<CryptoBase> crypto;
    const Mpz plaintext_input{ "28548163919765868" };
    const std::vector<Mpz> expected_ciphertext_output = {
       Mpz("236154725924767980551150673330103777948241812238232918563860"),
       Mpz("334914684833931523417345434823773865877240498516797745945354")
    };

	//Στο ElGamal συγκεκριμένα, το private key (a) παράγεται τυχαία, για να έχουμε ντετερμινιστικά αποτελέσματα
	//θα πρέπει να αρχικοποιήσουμε και το private key με κατι σταθερό
    void SetUp() override {
        const Mpz p("816515361624733876864538625588406301264004313976452317790849");
        const Mpz a("306765337773201296848538220196722535718712641031736429952667");
        crypto = std::make_unique<CryptoElGamal>(p, a);
    }
};

//Αρχικοποίηση ElGamal
TEST_F(TestFixtureElGamal, Initialize) {
    const Mpz elgamal_decimal_value = crypto->english_to_decimal("elgamal");
    EXPECT_FALSE(elgamal_decimal_value.is_empty());
    EXPECT_EQ(plaintext_input, elgamal_decimal_value);
}

//Encryption test, στο ElGamal τα ciphertext είναι δυο.
//το αποτελεσμα της κρυπτογράφησης δεν είναι σταθερό, ακόμα και με σταθερά public/private keys
//μπορύμε να ελέγξουμε αν απλώς πέτυχε η κρυπτογράφηση
TEST_F(TestFixtureElGamal, Encrypt) {
    std::vector<Mpz> ciphertext(2);
    EXPECT_TRUE(crypto->encrypt(plaintext_input, ciphertext));
	EXPECT_TRUE(!ciphertext[0].is_empty() && !ciphertext[1].is_empty());
}

//Decryption test
TEST_F(TestFixtureElGamal, Decrypt) {
    cout << plaintext_input << "\n";
    cout << crypto->decrypt(expected_ciphertext_output) << "\n";
    EXPECT_EQ(plaintext_input, crypto->decrypt(expected_ciphertext_output));
}

//Decode test
TEST_F(TestFixtureElGamal, Decode) {
    EXPECT_FALSE(CryptoBase::decimal_to_english(plaintext_input).empty());
}
