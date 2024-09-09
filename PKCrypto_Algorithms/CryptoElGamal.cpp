#include "CryptoElGamal.h"
#include "Mpz.h"
#include <iostream>

using std::cout;

void CryptoElGamal::initialize_parameters() {
    //p: random prime
    while (true) {
        //δημιουργία του p
        p.Mpz_urandomb(state, key_size);
        if (p.Mpz_probab_prime_p(30) >= 1)
            break;
    }

    //Είναι σύνηθες να ισχύει (p-1) = 2g οπότε g (γεννήτορας Z*p) = (p-1)/2
    gmp::Mpz p_minus_one;

    p_minus_one.Mpz_sub_ui(p, 1); //p-1
    g.Mpz_fdiv_q_ui(p_minus_one, 2); // g = (p - 1) / 2

    //εύρεση του a (το οποίο είναι ο εκθέτης στο g^a mod p το οποίο είναι το public key)
    //το α ειναι ενας τυχαιος στο διαστημα [0,p-2]
    gmp::Mpz p_minus_two;
    p_minus_two.Mpz_sub_ui(p, 2); //p-2
    while (true) {
        a.Mpz_urandomb(state, key_size);
        if (a.Mpz_cmp(p_minus_two) <= 0) {
            break;
        }
    }

    //a = private key, υπολογίζουμε το g^a mod p που ειναι το public key
    public_key.Mpz_powm(g, a, p);
}

void CryptoElGamal::print_parameters() const {
    cout << "p = ";
    p.Mpz_out_str();
    cout << "\n\ng = ";
    g.Mpz_out_str();
    cout << "\n\nPublic key = ";
    public_key.Mpz_out_str();
    cout << "\n\nPrivate key = ";
    a.Mpz_out_str();
    cout << "\n\n";
}

bool CryptoElGamal::encrypt(const gmp::Mpz &input, gmp::Mpz &c1,  gmp::Mpz &c2) {
    if (input.size_in_bits() >= key_size)
        return false;
    //δημιουργια του k, 1<=k<=p-2
    gmp::Mpz k, p_minus_two;
    p_minus_two.Mpz_sub_ui(p, 2);

    while (true) {
        k.Mpz_urandomb(state, key_size);
        //έλεγχος αν k>=1 και k<=p-2, αν ναι τοτε break
        if (k.Mpz_cmp(p_minus_two) <= 0 && k.Mpz_cmp_ui(1) >= 0)
            break;
    }

    //1: c1 = g^k mod p
    //2: c2 = plaintext * (public_key)^k mod p
    //τα c1,c2 είναι το ciphertext

    //c1
    c1.Mpz_powm(g, k, p);

    //c2
    //πολλαπλασιαστικός κανόνας: (plaintext * (public_key)^k) mod p = ( (plaintext mod p )*( public_key^k mod p ) ) mod p
    gmp::Mpz plaintext_mod_p, public_key_mod_p, intermediate;

    plaintext_mod_p.Mpz_mod(input, p);//plaintext_mod_p = plaintext MOD p
    public_key_mod_p.Mpz_powm(public_key, k, p); //public_key_mod_p = public_key^k MOD p
    intermediate.Mpz_mul(plaintext_mod_p, public_key_mod_p); //intermediate το γινόμενο
    //c2 = intermediate MOD p
    c2.Mpz_mod(intermediate, p);
    return true;
}

void CryptoElGamal::decrypt(const gmp::Mpz &c1, const gmp::Mpz &c2, gmp::Mpz &plaintext) const {
    gmp::Mpz intermediate, exponential, temp;

    //p-1-private
    temp.Mpz_sub_ui(p, 1);
    exponential.Mpz_sub(temp, a); //exponential = p-1-private_key

    //intermediate = c1 ^ (p - 1 - private_key) mod p
    intermediate.Mpz_powm(c1, exponential, p);

    //αποκρυπτογράφηση ως intermediate * c2 mod p
    gmp::Mpz temp2;
    temp2.Mpz_mul(intermediate, c2); //temp2 = intermediate*c2
    plaintext.Mpz_mod(temp2, p); // plaintext = temp2 mod p
}
