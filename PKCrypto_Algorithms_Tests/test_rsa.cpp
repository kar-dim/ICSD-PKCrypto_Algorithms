#include "../PKCrypto_Algorithms/CryptoBase.h"
#include "../PKCrypto_Algorithms/CryptoRSA.h"
#include "../PKCrypto_Algorithms/Mpz.h"
#include <gtest/gtest.h>
#include <iostream>
#include <memory>

using namespace gmp;
using std::cout;

class TestFixtureRSA : public ::testing::Test {
protected:
	std::unique_ptr<CryptoBase> crypto;
    const Mpz plaintext_input_ascii{ "114115097" };
    const Mpz expected_ciphertext_output{ "128212436976942807447413894514432885776652830497951807113198484535557160392454182204316361112687085168409355387650354089155794757738165712183136300248779823023574084443168737483906637122571684435775963759543805898098787897589659804888921079229753610277091770004039582269759641796106125267346283729667979719743" };
    
    void SetUp() override {
        const Mpz p("13174922939916297218567908474472490669546617046697150383644923516954371230034079308682703266474399778008345185926649826166595706429011056878196896853120041");
        const Mpz q("10524440994562082758573369754781353609847357361452562550995507517815311127791310031456280075943902699369026720841996900271872923300711438978484386631004087");
        crypto = std::make_unique<CryptoRSA>(p,q);
    }
};

//Αρχικοποίηση RSA
TEST_F(TestFixtureRSA, Initialize) {
  const Mpz rsa_decimal_value = crypto->english_to_decimal("rsa");
  EXPECT_FALSE(rsa_decimal_value.is_empty());
  EXPECT_EQ(plaintext_input_ascii, rsa_decimal_value);
}

//Encryption test
TEST_F(TestFixtureRSA, Encrypt) {
    Mpz ciphertext[1];
    EXPECT_TRUE(crypto->encrypt(plaintext_input_ascii, ciphertext));
    EXPECT_EQ(expected_ciphertext_output, *ciphertext);
}

//Decryption test
TEST_F(TestFixtureRSA, Decrypt) {
	EXPECT_EQ(plaintext_input_ascii, crypto->decrypt(&expected_ciphertext_output));
}

//Decode test
TEST_F(TestFixtureRSA, Decode) {
    const std::string decoded = CryptoBase::decimal_to_english(plaintext_input_ascii);
    EXPECT_FALSE(decoded.empty());
}
    