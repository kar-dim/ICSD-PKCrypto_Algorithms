#include "CryptoBase.h"
#include "CryptoRSA.h"
#include "Mpz.h"
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <vector>

using namespace gmp;
using std::cout;

class TestFixtureRSA : public ::testing::Test {
protected:
	std::unique_ptr<CryptoBase> crypto;
    const Mpz plaintext_input{ "7500641" };
    const std::vector<Mpz> expected_ciphertext_output = {
        Mpz("33867055612608072080291628746732225378260230374240448363928596079709585760334396972305963182402337849172182051508714348127014330615138107753331599208429211620093406323981603776836910084819325377304429798467990681888564218855202208266404024318108057241485446081837385924762128851462484197432944302258322103175")
    };
    
    void SetUp() override {
        const Mpz p("8852829144581428394071570206879428522163295384022503410914791602446638486001274510899722945605044461868274036758818841550278016814872685510683733296349933");
        const Mpz q("12893793985892681993155474887368231280457451623149307733018401758641484986371110269484871573822154316964139906841020343638781477145138458957939618526813391");
        crypto = std::make_unique<CryptoRSA>(p,q);
    }
};

//Αρχικοποίηση RSA
TEST_F(TestFixtureRSA, Initialize) {
  const Mpz rsa_decimal_value = crypto->english_to_decimal("rsa");
  EXPECT_FALSE(rsa_decimal_value.is_empty());
  EXPECT_EQ(plaintext_input, rsa_decimal_value);
}

//Encryption test
TEST_F(TestFixtureRSA, Encrypt) {
    std::vector<Mpz> ciphertext(1);
    EXPECT_TRUE(crypto->encrypt(plaintext_input, ciphertext));
    EXPECT_EQ(expected_ciphertext_output[0], ciphertext[0]);
}

//Decryption test
TEST_F(TestFixtureRSA, Decrypt) {
	EXPECT_EQ(plaintext_input, crypto->decrypt(expected_ciphertext_output));
}

//Decode test
TEST_F(TestFixtureRSA, Decode) {
    EXPECT_FALSE(CryptoBase::decimal_to_english(plaintext_input).empty());
}
    