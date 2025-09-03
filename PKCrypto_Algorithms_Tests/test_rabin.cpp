#include "CryptoBase.h"
#include "CryptoRabin.h"
#include "Mpz.h"
#include <gtest/gtest.h>
#include <iostream>
#include <memory>

using namespace gmp;
using std::cout;

class TestFixtureRabin : public ::testing::Test {
protected:
    std::unique_ptr<CryptoBase> crypto;
    const Mpz plaintext_input_ascii{ "114097098105110" };
    const Mpz plaintext_input_ascii_padded { "114097098105110111111111111" };
    const std::vector<Mpz> expected_ciphertext_output = {
       Mpz("13018147796007121307518802099101879433432320987654321")
	};

    void SetUp() override {
        const Mpz p("278239804937272062342465215710021372388608714560106972047259");
        const Mpz q("1059438776216884344410115721981267794496600387388764531479287");
        crypto = std::make_unique<CryptoRabin>(p, q);
    }
};

//Αρχικοποίηση Rabin
TEST_F(TestFixtureRabin, Initialize) {
    const Mpz rabin_decimal_value_padded = crypto->english_to_decimal("rabin");
    EXPECT_FALSE(rabin_decimal_value_padded.is_empty());
    EXPECT_EQ(plaintext_input_ascii_padded, rabin_decimal_value_padded);
}

//Encryption test
TEST_F(TestFixtureRabin, Encrypt) {
    std::vector<Mpz> ciphertext(1);
    EXPECT_TRUE(crypto->encrypt(plaintext_input_ascii_padded, ciphertext));
    EXPECT_EQ(expected_ciphertext_output[0], ciphertext[0]);
}

//Decryption test
TEST_F(TestFixtureRabin, Decrypt) {
    EXPECT_EQ(plaintext_input_ascii, crypto->decrypt(expected_ciphertext_output));
}

//Decode test
TEST_F(TestFixtureRabin, Decode) {
    EXPECT_FALSE(CryptoBase::decimal_to_english(plaintext_input_ascii).empty());
}