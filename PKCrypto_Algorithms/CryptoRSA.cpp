#include "CryptoBase.h"
#include "CryptoRSA.h"
#include "Mpz.h"
#include <iostream>

using std::cout;
using gmp::Mpz;

CryptoRSA::CryptoRSA(): CryptoBase() {
    e = e_value;
}

void CryptoRSA::print_parameters() const {
    cout << "p = " << p << "\n\n" << "q = " << q << "\n\n" << "n = " << n << "\n\n" << "phi = " << totient
         << "\n\n" << "Public key is n and e = 65537" << "\n\n" << "Private key = " << d << "\n\n";
}

void CryptoRSA::initialize_parameters() {
    //πρέπει να αρχικοποιήσουμε το p και το q ώστε να είναι prime
    while (true) {
        //δημιουργία των δυο τυχαίων
        p = Mpz::urandomb(state, key_size);
        q = Mpz::urandomb(state, key_size);
        if (Mpz::probab_prime_p(p, 30) >= 1 && Mpz::probab_prime_p(q, 30) >= 1)
            break;
    }
    //εφόσον p,q είναι prime μπορούμε να υπολογίσουμε το n=pq
    n = p * q;
    public_key_size = n.size_in_bits();
    //ευρεση του (phi) totient = (p-1)(q-1)
    totient = (p - 1) * (q - 1);
}

//συνάρτηση του επεκταμένου αλγορίθμου του Ευκλείδη
//βρίσκει τον αντίστροφο του a mod m, δηλαδή a*p1 == 1(mod m) -> a*p1 = km + 1
bool CryptoRSA::e_euclid() {
    Mpz t, q, q_mul_p0;
    Mpz e_copy(e), p0(0), p1(1), totient_copy(totient);
    const Mpz m0(totient); //m0 είναι το αρχικό m, σε περίπτωση που βγει αρνητικό το αποτέλεσμα να το προσθέσουμε κατά m

    //περίπτωση όπου a*p1 mod 1 = 1 mod 1. -> a*p1 mod 1 = 0. Η ομάδα έχει 1 στοιχείο, το {0}
    if (totient == 1)
        return false;

    //επαναληπτικά μέχρι να μη μπορεί να μειωθεί και άλλο το a
    while (e_copy > 1) {
        q = e_copy / totient_copy;
        t = totient_copy;
        totient_copy = e_copy % totient_copy;
        e_copy = t;
        //pi =p(i-2) - p(i-1) q(i-2)(mod n), pi είναι το p1, το p(i-2) είναι το t και p(i-1) είναι το p0
        t = p0;
        //p(i-1) = p0
        p0 = p1 - (q * p0);
        p1 = t;
    }
    //αν ο inverse είναι αρνητικός τον κάνουμε θετικό κατά m0 = το αρχικό m για να οριζεται στο (0, m-1)
    if (p1 < 0)
        p1 += m0;
    //d=p1, το private key είναι ο inverse
    d = p1;
    return true;
}

bool CryptoRSA::encrypt(const Mpz &rsa_decimal_value, Mpz &ciphertext) const {
    if (rsa_decimal_value.size_in_bits() > public_key_size - 1)
        return false;
    ciphertext = Mpz::powm(rsa_decimal_value, e, n);
    return true;
}

Mpz CryptoRSA::decrypt(const Mpz &ciphertext) const {
    return Mpz::powm(ciphertext, d, n);
}
