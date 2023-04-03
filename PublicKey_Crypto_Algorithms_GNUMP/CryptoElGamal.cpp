#include "CryptoElGamal.h"
#include <gmp.h>
#include <iostream>

using std::cout;

void CryptoElGamal::init() {
	CryptoBase::init();
    mpz_init(p);
    mpz_init(g);
    mpz_init(a); //a=private key
    mpz_init(public_key);
}

void CryptoElGamal::initialize_parameters() {
    //p: ενας prime 200 bits, δίνουμε random τιμή και ελέγχουμε αν είναι prime
    while (true) {
        //δημιουργία του p
        mpz_urandomb(p, state, 200);
        if (mpz_probab_prime_p(p, 30) >= 1) {
            break;
        }
    }

    //Είναι σύνηθες να ισχύει (p-1) = 2g οπότε g = (p-1)/2
    mpz_t p_minus_one;
    mpz_init(p_minus_one);

    mpz_sub_ui(p_minus_one, p, 1); //p-1
    mpz_fdiv_q_ui(g, p_minus_one, 2); //g = (p-1)/2

    mpz_clear(p_minus_one);
    //πλέον έχουμε έναν random prime p 200bits και τον γεννήτορα του Z*p

    //εύρεση του a (το οποίο είναι ο εκθέτης στο g^a mod p το οποίο είναι το public key)
    //το α ειναι ενας τυχαιος στο διαστημα [0,p-2
    mpz_t p_minus_two;
    mpz_init(p_minus_two);
    mpz_sub_ui(p_minus_two, p, 2); //p-2
    while (true) {
        mpz_urandomb(a, state, 200);
        if (mpz_cmp(a, p_minus_two) <= 0) {
            break;
        }
    }
    mpz_clear(p_minus_two);
    //a = private key, υπολογίζουμε το g^a mod p που ειναι το public key
    mpz_powm(public_key, g, a, p);
}

void CryptoElGamal::print_parameters() {
    cout << "p = ";
    mpz_out_str(NULL, 10, p);
    cout << "\n\n";
    cout << "g = ";
    mpz_out_str(NULL, 10, g);
    cout << "\n\n";
    cout << "Public key = ";
    mpz_out_str(NULL, 10, public_key);
    cout << "\n\n";
    cout << "Private key = ";
    mpz_out_str(NULL, 10, a);
    cout << "\n\n";
}

void CryptoElGamal::encrypt(mpz_t input, mpz_t c1, mpz_t c2) {
    mpz_init(c1);
    mpz_init(c2);
    //δημιουργια του k, 1<=k<=p-2
    mpz_t k, p_minus_two;
    mpz_init(p_minus_two);
    mpz_init(k);
    mpz_sub_ui(p_minus_two, p, 2); //p-2

    while (true) {
        mpz_urandomb(k, state, 200);
        //έλεγχος αν k>=1 και k<=p-2, αν ναι τοτε break
        if (mpz_cmp(k, p_minus_two) <= 0 && mpz_cmp_ui(k, 1) >= 0) {
            break;
        }
    }
    mpz_clear(p_minus_two);
    //1: c1 = g^k mod p
    //2: c2 = plaintext * (public_key)^k mod p
    //τα c1,c2 είναι το ciphertext

    //c1
    mpz_powm(c1, g, k, p);

    //c2
    //gnump δεν επιτρέπει το public_key^k διότι k δεν είναι μικρός ακέραιος αλλά mpz_t (επιτρέπει μόνο x^y αν x είναι mpz_t και y=μικρος ακεραιος)
    //θα εφαρμόσουμε τον πολλαπλασιαστικό κανόνα: (plaintext * (public_key)^k) mod p = ( (plaintext mod p )*( public_key^k mod p ) ) mod p
    mpz_t plaintext_mod_p, public_key_mod_p, intermediate;
    mpz_init(plaintext_mod_p);
    mpz_init(public_key_mod_p);
    mpz_init(intermediate);

    mpz_mod(plaintext_mod_p, input, p); //plaintext_mod_p = plaintext MOD p
    mpz_powm(public_key_mod_p, public_key, k, p); //public_key_mod_p = public_key^k MOD p
    mpz_mul(intermediate, plaintext_mod_p, public_key_mod_p); //intermediate το γινόμενο
    //c2 = intermediate MOD p
    mpz_mod(c2, intermediate, p);

    mpz_clear(plaintext_mod_p);
    mpz_clear(public_key_mod_p);
    mpz_clear(intermediate);
}

void CryptoElGamal::decrypt(mpz_t c1, mpz_t c2, mpz_t plaintext) {
    mpz_init(plaintext);
    //υπολογίζεται το ενδιάμεσο intermediate = c1 ^ (p - 1 - private_key) mod p
    //στη συνέχεια αποκρυπτογραφείται ως intermediate * c2 mod p
    mpz_t intermediate, exponential, temp;
    mpz_init(intermediate);
    mpz_init(exponential);
    mpz_init(temp);
    //p-1-private
    mpz_sub_ui(temp, p, 1);
    mpz_sub(exponential, temp, a); //exponential = p-1-private_key
    mpz_clear(temp);

    //τώρα θα υπολογίσουμε το intermediate
    mpz_powm(intermediate, c1, exponential, p);

    //αποκρυπτογράφηση ως intermediate * c2 mod p
    mpz_t temp2;
    mpz_init(temp2);
    mpz_mul(temp2, intermediate, c2); //temp2 = intermediate*c2
    mpz_mod(plaintext, temp2, p); // plaintext = temp2 mod p

    mpz_clear(temp2);
    mpz_clear(intermediate);
}
