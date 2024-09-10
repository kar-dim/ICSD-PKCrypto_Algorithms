#include "CryptoBase.h"
#include "CryptoRSA.h"
#include "Mpz.h"
#include <iostream>

using std::cout;

CryptoRSA::CryptoRSA(): CryptoBase() {
    e.Mpz_set_ui(e_value);
}

void CryptoRSA::print_parameters() const {
    cout << "p = ";
    p.Mpz_out_str();
    cout << "\n\nq = ";
    q.Mpz_out_str();
    cout << "\n\nn = ";
    n.Mpz_out_str();
    cout << "\n\nphi = ";
    totient.Mpz_out_str();
    cout << "\n\nPublic key is n and e = 65537\n\n";
}

void CryptoRSA::print_private_key() const {
    cout << "private key = ";
    d.Mpz_out_str();
    cout << "\n\n";
}

void CryptoRSA::initialize_parameters() {
    //πρέπει να αρχικοποιήσουμε το p και το q ώστε να είναι prime
    while (true) {
        //δημιουργία των δυο τυχαίων
        p.Mpz_urandomb(state, key_size);
        q.Mpz_urandomb(state, key_size);
        if (p.Mpz_probab_prime_p(30) >= 1 && q.Mpz_probab_prime_p(30) >= 1) {
            break;
        }
    }
    //εφόσον p,q είναι prime μπορούμε να υπολογίσουμε το n=pq
    n.Mpz_mul(p, q);

    //ευρεση του phi
    gmp::Mpz p_minus_one, q_minus_one;

    //p_minus_one = (p-1)
    p_minus_one.Mpz_sub_ui(p, 1);
    //q_minus_one = (q-1)
    q_minus_one.Mpz_sub_ui(q, 1);
    // totient = (p-1)(q-1)
    totient.Mpz_mul(p_minus_one, q_minus_one);
}

//συνάρτηση του επεκταμένου αλγορίθμου του Ευκλείδη
//βρίσκει τον αντίστροφο του a mod m, δηλαδή a*p1 == 1(mod m) -> a*p1 = km + 1
bool CryptoRSA::e_euclid() {
    gmp::Mpz t, q, q_mul_p0;
    gmp::Mpz e_copy(e), p0(0), p1(1), totient_copy(totient);
    const gmp::Mpz m0(totient); //m0 είναι το αρχικό m, σε περίπτωση που βγει αρνητικό το αποτέλεσμα να το προσθέσουμε κατά m

    //περίπτωση όπου a*p1 mod 1 = 1 mod 1. -> a*p1 mod 1 = 0. Η ομάδα έχει 1 στοιχείο, το {0}
    if (totient.Mpz_cmp_ui(1) == 0)
        return false;

    //επαναληπτικά μέχρι να μη μπορεί να μειωθεί και άλλο το a
    while (e_copy.Mpz_cmp_ui(1) > 0) {
        q.Mpz_fdiv_q(e_copy, totient_copy); //q= αποτέλεσμα διαίρεσης
        t = totient_copy;

        totient_copy.Mpz_mod(e_copy, totient_copy);
        e_copy = t;

        //pi =p(i-2) - p(i-1) q(i-2)(mod n), pi είναι το p1, το p(i-2) είναι το t και p(i-1) είναι το p0
        t = p0;

        //p(i-1) = p0
        q_mul_p0.Mpz_mul(q, p0);
        p0.Mpz_sub(p1, q_mul_p0);

        p1 = t;
    }
    //αν ο inverse είναι αρνητικός τον κάνουμε θετικό κατά m0 = το αρχικό m για να οριζεται στο (0, m-1)
    if (p1.Mpz_cmp_ui(0) < 0) {
        p1.Mpz_add(p1, m0);
    }
    //d=p1, το private key είναι ο inverse
    d = p1;
    return true;
}

bool CryptoRSA::encrypt(const gmp::Mpz &rsa_decimal_value, gmp::Mpz &ciphertext) const {
    if (rsa_decimal_value.size_in_bits() >= 2 * key_size)
        return false;
    ciphertext.Mpz_powm(rsa_decimal_value, e, n);
    return true;
}

void CryptoRSA::decrypt(gmp::Mpz &plaintext, const gmp::Mpz &ciphertext) const {
    plaintext.Mpz_powm(ciphertext, d, n);
}
