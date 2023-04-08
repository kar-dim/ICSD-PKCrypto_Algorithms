#include "CryptoRSA.h"
#include <gmp.h>
#include <iostream>
#include "Mpz.h"

using std::cout;

CryptoRSA::CryptoRSA(): CryptoBase() {
    //αρχικοποίηση των p,q,n, totient στο 0 και e
    e.Mpz_set_ui(65537);
}

void CryptoRSA::print_parameters() {
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

void CryptoRSA::print_private_key() {
    cout << "private key = ";
    d.Mpz_out_str();
    cout << "\n\n";
}

void CryptoRSA::initialize_parameters() {
    //πρέπει να αρχικοποιήσουμε το p και το q ώστε να είναι prime 512bits
    while (true) {
        //δημιουργία των δυο τυχαίων
        p.Mpz_urandomb(state, 512);
        q.Mpz_urandomb(state, 512);
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
unsigned int CryptoRSA::e_euclid() {
    gmp::Mpz t, q, totient_copy, q_mul_p0;
    //αρχικά p0=0, p1=1
    gmp::Mpz p0(0UL);
    gmp::Mpz p1(1);

    gmp::Mpz m0(totient); //m0 είναι το αρχικό m, σε περίπτωση που βγει αρνητικό το αποτέλεσμα να το προσθέσουμε κατά m
    //για παράδειγμα ομάδα 10 στοιχείων, {0,1,...9}, το -3 είναι το στοιχείο 6 στο Ζ10

    //περίπτωση όπου a*p1 mod 1 = 1 mod 1. -> a*p1 mod 1 = 0. Η ομάδα έχει 1 στοιχείο, το {0}
    if (totient.Mpz_cmp_ui(1) == 0)
        return 0;

    //επαναληπτικά μέχρι να μη μπορεί να μειωθεί και άλλο το a
    while (e.Mpz_cmp_ui(1) > 0) {
        q.Mpz_fdiv_q(e, totient); //q= αποτέλεσμα διαίρεσης
        t = totient;  //(t, totient);

        totient_copy = totient; //mpz_set(totient_copy, totient);
        totient.Mpz_mod(e, totient_copy); //m = αποτέλεσμα a MOD m
        e = t; //mpz_set(e, t);

        //ενημερώνουμε τα p0,p1.
        //pi =p(i-2) - p(i-1) q(i-2)(mod n), pi είναι το p1, το p(i-2) είναι το t και p(i-1) είναι το p0
        t = p0; // mpz_set(t, p0); //p(i-2) = t

        //p(i-1) = p0
        q_mul_p0.Mpz_mul(q, p0);// mpz_mul(q_mul_p0, q, p0);
        p0.Mpz_sub(p1, q_mul_p0); // mpz_sub(p0, p1, q_mul_p0);

        p1 = t; // mpz_set(p1, t); //pi = p1
    }
    //αν ο inverse είναι αρνητικός τον κάνουμε θετικό κατά m0 = το αρχικό m
    //ώστε να είναι μέσα στην ομάδα που πρέπει να ορίζεται (0, m-1)
    if (p1.Mpz_cmp_ui(0)/*/mpz_cmp_ui(p1, 0)*/ < 0) {
        gmp::Mpz copy_p1(p1); //mpz_init_set(copy_p1, p1);
        //εδώ γίνεται η πρόσθεση με το m0
        p1.Mpz_add(copy_p1, m0); // mpz_add(p1, copy_p1, m0);
    }
    //d=p1, το private key είναι ο inverse
    d = p1;// mpz_set(d, p1);

    return 0;
}

void CryptoRSA::encrypt(const gmp::Mpz &rsa_decimal_value, gmp::Mpz &ciphertext) {
    gmp::Mpz m_to_e;
    //m_to_e = m^e
    m_to_e.Mpz_pow_ui(rsa_decimal_value, 65537);
    //ciphertext = m_to_e MOD n
    ciphertext.Mpz_mod(m_to_e, n);

}

void CryptoRSA::decrypt(gmp::Mpz &plaintext, const gmp::Mpz &ciphertext) {
    plaintext.Mpz_powm(ciphertext, d, n);
}
