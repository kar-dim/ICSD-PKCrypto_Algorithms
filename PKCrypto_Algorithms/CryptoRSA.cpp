#include "CryptoBase.h"
#include "CryptoRSA.h"
#include "Mpz.h"
#include <iostream>
#include <stdexcept>
#include <vector>

using std::cout;
using gmp::Mpz;

CryptoRSA::CryptoRSA() : CryptoBase() {
    e = e_value;
    do {
        //πρέπει να αρχικοποιήσουμε το p και το q ώστε να είναι prime
        while (true) {
            p = Mpz::urandomb(state, key_factors_max_size);
            q = Mpz::urandomb(state, key_factors_max_size);
            if (Mpz::probab_prime_p(p, 30) >= 1 && Mpz::probab_prime_p(q, 30) >= 1)
                break;
        }
        //εφόσον p,q είναι prime μπορούμε να υπολογίσουμε το n=pq
        n = p * q;
        //ευρεση του (phi) totient = (p-1)(q-1)
        totient = (p - 1) * (q - 1);
    } while (!e_euclid());
}

//constructor για αρχικοποίηση με σταθερά p,q (κυρίως για test)
//p και q πρέπει να είναι valid, δηλαδή να υπάρχει ο αντίστροφος στο euclid test, αλλιώς πετάμε exception
CryptoRSA::CryptoRSA(const Mpz& p, const Mpz& q) : CryptoBase(), e(e_value), p(p), q(q), n(p * q), totient((p - 1)* (q - 1)) {
	if (!e_euclid())
		throw std::invalid_argument("p and q do not pass the euclid test!");
}

void CryptoRSA::print_parameters() const {
    cout << "p = " << p << "\n\n" << "q = " << q << "\n\n" << "n = " << n << "\n\n" << "phi = " << totient
         << "\n\n" << "Public key is n and e = 65537" << "\n\n" << "Private key = " << d << "\n\n";
}

//συνάρτηση του επεκταμένου αλγορίθμου του Ευκλείδη
//βρίσκει τον αντίστροφο του a mod m, δηλαδή a*p1 == 1(mod m) -> a*p1 = km + 1
bool CryptoRSA::e_euclid() {
    Mpz t, q, q_mul_p0;
    Mpz e_copy(e), p0(0), p1(1), totient_copy(totient);

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
        p1 += totient;
    //d=p1, το private key είναι ο inverse
    d = p1;
    return true;
}

bool CryptoRSA::encrypt(const Mpz& cleartext, std::vector<Mpz>& ciphertext) {
    if (cleartext >= n)
        return false;
    ciphertext[0] = Mpz::powm(cleartext, e, n);
    return true;
}

Mpz CryptoRSA::decrypt(const std::vector<Mpz>& ciphertext) {
    return Mpz::powm(ciphertext[0], d, n);
}
