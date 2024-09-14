#include "CryptoElGamal.h"
#include "Mpz.h"
#include <iostream>

using std::cout;
using gmp::Mpz;

void CryptoElGamal::initialize_parameters() {
    //p: random prime
    while (true) {
        //δημιουργία του p
        p = Mpz::urandomb(state, key_size);
        if (Mpz::probab_prime_p(p, 30) >= 1)
            break;
    }
    public_key_size = p.size_in_bits();

    //Είναι σύνηθες να ισχύει (p-1) = 2g οπότε g (γεννήτορας Z*p) = (p-1)/2
    g = (p - 1) / 2;

    //εύρεση του a (το οποίο είναι ο εκθέτης στο g^a mod p το οποίο είναι το public key)
    //το α ειναι ενας τυχαιος στο διαστημα [0,p-2]
    const Mpz p_minus_two = p - 2;
    while (true) {
        a = Mpz::urandomb(state, key_size);
        if (a <= p_minus_two)
            break;
    }
    //a = private key, υπολογίζουμε το g^a mod p που ειναι το public key
    public_key = Mpz::powm(g, a, p);
}

void CryptoElGamal::print_parameters() const {
    cout << "p = " << p << "\n\n" << "g = " << g << "\n\n"
         << "Public key = " << public_key << "\n\n" << "Private key = " << a << "\n\n";
}

bool CryptoElGamal::encrypt(const Mpz &input, Mpz &c1,  Mpz &c2) {
    if (input.size_in_bits() > public_key_size - 1)
        return false;

    //δημιουργια του k, 1<=k<=p-2
    const Mpz p_minus_two = p - 2;
    Mpz k;
    while (true) {
        k = Mpz::urandomb(state, key_size);
        //έλεγχος αν k<=p-2 και k>=1, αν ναι τοτε break
        if (k <= p_minus_two && k >= 1)
            break;
    }

    //c1 = g^k mod p
    c1 = Mpz::powm(g, k, p);

    //c2 = plaintext * (public_key)^k mod p
    //πολλαπλασιαστικός κανόνας: (plaintext * (public_key)^k) mod p = ( (plaintext mod p )*( public_key^k mod p ) ) mod p
    c2 = ((input % p) * Mpz::powm(public_key, k, p)) % p;
    return true;
}

Mpz CryptoElGamal::decrypt(const Mpz &c1, const Mpz &c2) const {
    //intermediate = c1 ^ (p - 1 - private_key) mod p
    Mpz intermediate = Mpz::powm(c1, (p - 1) - a, p);
    //αποκρυπτογράφηση ως intermediate * c2 mod p
    return (intermediate * c2 ) % p;
}
