#include "CryptoBase.h"
#include "CryptoRabin.h"
#include "Mpz.h"
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <vector>

using namespace gmp;
using std::cout;

class TestFixtureRabin : public ::testing::Test {
protected:
    std::unique_ptr<CryptoBase> crypto;
    const Mpz plaintext_input{ "491260111214" };
    const Mpz plaintext_input_padded { "49126011121411111111111" };
    const std::vector<Mpz> expected_ciphertext_output = {
       Mpz("2413364968701008174673980317676540920987654321")
	};

    void SetUp() override {
        const Mpz p("118205388268997221215522816252042850181310718543331407699847");
        const Mpz q("986540242549875195011522722646531578730080753561808834074711");
        crypto = std::make_unique<CryptoRabin>(p, q);
    }
};

//Αρχικοποίηση Rabin
TEST_F(TestFixtureRabin, Initialize) {
    const Mpz rabin_decimal_value_padded = crypto->english_to_decimal("rabin");
    EXPECT_FALSE(rabin_decimal_value_padded.is_empty());
    EXPECT_EQ(plaintext_input_padded, rabin_decimal_value_padded);
}

//Encryption test
TEST_F(TestFixtureRabin, Encrypt) {
    std::vector<Mpz> ciphertext(1);
    EXPECT_TRUE(crypto->encrypt(plaintext_input_padded, ciphertext));
    EXPECT_EQ(expected_ciphertext_output[0], ciphertext[0]);
}

//Decryption test
TEST_F(TestFixtureRabin, Decrypt) {
    EXPECT_EQ(plaintext_input, crypto->decrypt(expected_ciphertext_output));
}

//Decode test
TEST_F(TestFixtureRabin, Decode) {
    EXPECT_FALSE(CryptoBase::decimal_to_english(plaintext_input).empty());
}