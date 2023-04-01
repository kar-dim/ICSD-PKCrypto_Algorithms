#include "CryptoRSA.h"
#include <gmp.h>
#include <iostream>

using std::cout;

void CryptoRSA::init() {
    CryptoBase::init();
    //αρχικοποίηση των p,q,n, totient στο 0 και e
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(totient);
    mpz_init(e);
    mpz_init(d);
    mpz_set_ui(e, 65537);
}

void CryptoRSA::print_parameters() {
    cout << "p = ";
    mpz_out_str(NULL, 10, p);
    cout << "\n\n";
    cout << "q = ";
    mpz_out_str(NULL, 10, q);
    cout << "\n\n";
    cout << "n = ";
    mpz_out_str(NULL, 10, n);
    cout << "\n\n";
    cout << "phi = ";
    mpz_out_str(NULL, 10, totient);
    cout << "\n\n";
    cout << "Public key is n and e = 65537\n\n";
}

void CryptoRSA::print_private_key() {
    printf("private key = ");
    mpz_out_str(NULL, 10, d);
    printf("\n\n");
}

void CryptoRSA::initialize_parameters() {
    //πρέπει να αρχικοποιήσουμε το p και το q ώστε να είναι 512bits αλλά και prime
    //θα χρησιμοποιήσουμε το Miller-Rabin test για να ελέγξουμε αν είναι prime

    //δίνουμε random τιμή και ελέγχουμε αν είναι prime
    while (true) {
        //δημιουργία των δυο τυχαίων
        mpz_urandomb(p, state, 512);
        mpz_urandomb(q, state, 512);
        //έλεγχος αν είναι prime, αν είναι τότε break, αλλιώς θα ξαναδημιουργηθούν πάλι δύο τυχαίοι
        //το 30 είναι ο αριθμός των επαναλήψεων για να ελεγθεί αν είναι prime
        if (mpz_probab_prime_p(p, 30) >= 1 && mpz_probab_prime_p(q, 30) >= 1) {
            break;
        }
    }
    //εφόσον p,q είναι prime μπορούμε να υπολογίσουμε το n=pq
    mpz_mul(n, p, q);

    //ευρεση του phi
    mpz_t p_minus_one;
    mpz_t q_minus_one;
    mpz_init(p_minus_one);
    mpz_init(q_minus_one);
    //p_minus_one = (p-1)
    mpz_sub_ui(p_minus_one, p, 1);
    //q_minus_one = (q-1)
    mpz_sub_ui(q_minus_one, q, 1);
    // totient = (p-1)(q-1)
    mpz_mul(totient, p_minus_one, q_minus_one);
    //εφόσον έχουμε το totient, δε χρειαζόμαστε τα p_minus_one και q_minus_one
    //οπότε τα αφαιρούμε από τη μνήμη
    mpz_clear(p_minus_one);
    mpz_clear(q_minus_one);
}

//συνάρτηση του επεκταμένου αλγορίθμου του Ευκλείδη
//βρίσκει τον αντίστροφο του a mod m, δηλαδή a*p1 == 1(mod m) -> a*p1 = km + 1
unsigned int CryptoRSA::e_euclid() {
    mpz_t t, q, p0, p1, m0, totient_copy, q_mul_p0;
    mpz_init(t);
    mpz_init(q);
    mpz_init(totient_copy);
    mpz_init(q_mul_p0);
    //αρχικά ξεκινάμε με p0=0, p1=1.
    mpz_init_set_ui(p0, 0);
    mpz_init_set_ui(p1, 1);
    mpz_init_set(m0, totient); //m0 είναι το αρχικό m, σε περίπτωση που βγει αρνητικό το αποτέλεσμα να το προσθέσουμε κατά m
    //για παράδειγμα ομάδα 10 στοιχείων, {0,1,...9}, το -3 είναι το στοιχείο 6 στο Ζ10

    //a*p1 mod 1 = 1 mod 1. -> a*p1 mod 1 = 0. Η ομάδα έχει 1 στοιχείο, το {0}
    //άρα ο αντίστροφος του μοναδικού στοιχείου άυτού είναι ο εαυτός του, δηλαδή το 0
    //mpz_cmp_ui επιστρέφει τιμή = 0 αν η σύγκριση είναι αληθές
    if (mpz_cmp_ui(totient, 1) == 0) {
        return 0;
    }
    //επαναληπτικά μέχρι να μη μπορεί να μειωθεί και άλλο το a
    while (mpz_cmp_ui(e, 1) > 0) {
        mpz_fdiv_q(q, e, totient); //q= αποτέλεσμα διαίρεσης το κρατάμε σε κάθε απανάληψη
        mpz_set(t, totient);

        mpz_set(totient_copy, totient);
        mpz_mod(totient, e, totient_copy); //m = αποτέλεσμα a MOD m, επίσης το κρατάμε σε κάθε επανάληψη
        mpz_set(e, t);

        //εδώ ενημερώνουμε τα p0,p1 κάθε φορά. Ο αλγόριθμος μας λέει πως
        //pi =p(i-2) - p(i-1) q(i-2)(mod n), εδώ το pi είναι το p1, το p(i-2) είναι το t
        //και p(i-1) είναι το p0
        mpz_set(t, p0); //p(i-2) = t

        //p(i-1) = p0
        mpz_mul(q_mul_p0, q, p0);
        mpz_sub(p0, p1, q_mul_p0);

        mpz_set(p1, t); //pi = p1
    }
    //αν ο inverse είναι αρνητικός τον κάνουμε θετικό κατά m0 = το αρχικό m
    //ώστε να είναι μέσα στην ομάδα που πρέπει να ορίζεται (0, m-1)
    if (mpz_cmp_ui(p1, 0) < 0) {
        mpz_t copy_p1;
        mpz_init_set(copy_p1, p1);
        //εδώ γίνεται η πρόσθεση με το m0
        mpz_add(p1, copy_p1, m0);
        //αποδέσμευση μνήμης
        mpz_clear(copy_p1);
    }
    //d=p1, το private key είναι ο inverse
    mpz_set(d, p1);

    //clear όλων των μεταβλητών που δε χρειαζόμαστε πλέον
    mpz_clear(p0);
    mpz_clear(p1);
    mpz_clear(t);
    mpz_clear(q);
    mpz_clear(m0);
    mpz_clear(totient_copy);
    mpz_clear(q_mul_p0);
    return 0;
}

void CryptoRSA::encrypt(mpz_t rsa_decimal_value, mpz_t ciphertext) {
    mpz_t m_to_e;
    mpz_init(ciphertext);
    mpz_init(m_to_e);

    //m_to_e = m^e
    mpz_pow_ui(m_to_e, rsa_decimal_value, 65537);

    //ciphertext = m_to_e MOD n
    mpz_mod(ciphertext, m_to_e, n);
    //σημείωση: η mpz_powm δε δουλεύει για κάποιο λόγο στη κρυπτογράφηση, οπότε
    //αντι να κάνω απευθείας την ύψωση και το modulo, τα έκανα ως 2 βήματα και δουλεύει
    //στην αποκρυπτογράφηση δουλεύει όμως η συνάρτηση mpz_powm.
    //mpz_powm(ciphertext, rsa_decimal_value, e, n); //ciphertext = m^e mod n
}

void CryptoRSA::decrypt(mpz_t plaintext, mpz_t ciphertext) {
    mpz_init(plaintext);
    mpz_powm(plaintext, ciphertext, d, n);
}
