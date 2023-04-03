#include "CryptoRabin.h"
#include <string>
#include <gmp.h>
#include <iostream>

using std::cout;

CryptoRabin::CryptoRabin(): CryptoBase() {
	mpz_init(p);
	mpz_init(q);
	mpz_init(n);
}

CryptoRabin::~CryptoRabin() {
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
}

void CryptoRabin::initialize_parameters() {
    //ευρεση δυο prime p,q ωστε p==q==3mod4, δηλαδή αν p MOD 4 = q MOD 4 = 3 mod 4 -> p MOD 4 = q MOD 4 = 3
    mpz_t temp_p, temp_q;
    mpz_init(temp_p);
    mpz_init(temp_q);
    while (true) {
        //δημιουργία των δυο τυχαίων μεγέθους 200bits
        mpz_urandomb(p, state, 200);
        mpz_urandomb(q, state, 200);
        //έλεγχος αν είναι prime, αν είναι τότε ελέγχουμε και την επιπλέον συνθήκη, αλλιώς θα ξαναδημιουργηθούν πάλι δύο τυχαίοι
        if (mpz_probab_prime_p(p, 30) >= 1 && mpz_probab_prime_p(q, 30) >= 1) {
            mpz_mod_ui(temp_p, p, 4);
            mpz_mod_ui(temp_q, q, 4);
            //εναλλακτικά μπορούσαμε με τη συνάρτηση mpz_congruent_p_ui_p απευθείας
            //έλεγχος αν είναι ίδια και ίσα με 3
            if (mpz_cmp_ui(temp_p, 3) == 0 && mpz_cmp_ui(temp_q, 3) == 0) {
                break;
            }
        }
    }
    //εφόσον p,q είναι prime μπορούμε να υπολογίσουμε το n=pq
    mpz_mul(n, p, q);
    //clear τα temp mpz_t
    mpz_clear(temp_p);
    mpz_clear(temp_q);
}

void CryptoRabin::print_parameters() {
    cout << "p = ";
    mpz_out_str(NULL, 10, p);
    cout << "\n\n";
    cout << "q = ";
    mpz_out_str(NULL, 10, q);
    cout << "\n\n";
    cout << "n = ";
    mpz_out_str(NULL, 10, n);
    cout << "\n\n";
}

bool CryptoRabin::english_to_decimal(mpz_t number, const std::string &word) {
    int size = (int)word.length();
    std::string characters_as_numbers = ""; //ένας τριψήφιος αριθμός είναι ένα γράμμα στο ASCII (pad με 0 μπροστά αν είναι διψήφιος)
    for (int i = 0; i < size; i++) {
        //παίρνουμε τη ASCII μορφή του χαρακτήρα
        int temp = (int)word[i];
        int num_of_digits = CryptoBase::number_of_digits(temp);
        if (num_of_digits <= 1 || num_of_digits > 3) {
            cout << "Not an English word, can't encrypt it!\n";
            return false;
        }
        //αν είναι 2ψήφιος τότε βάζουμε ένα 0 μπροστά
        characters_as_numbers += num_of_digits == 2 ? '0' : (get_digit(temp, 2) + '0');
        characters_as_numbers += (get_digit(temp, 1) + '0');
        characters_as_numbers += (get_digit(temp, 0) + '0');
    }
    //padding
    characters_as_numbers += "111111111111";
    cout << "Encoded characters (plus redundancy): " << characters_as_numbers << "\n\n";
    mpz_init(number);
    if (mpz_set_str(number, characters_as_numbers.c_str(), 10) == -1) {
        cout << "Failed to encode the word! Can't encrypt\n";
        return false;
    }
    return true;
}

void CryptoRabin::encrypt(mpz_t plaintext, mpz_t ciphertext) {
    mpz_init(ciphertext);
    mpz_powm_ui(ciphertext, plaintext, 2, n);
}

//επεκταμένος αλγόριθμος του Ευκλείδη που βρίσκει τα x,y ώστε ax + by = 1
//(απευθείας εφαρμογή του βιβλίου "Handbook of Applied Cryptography" )
void CryptoRabin::euclid(mpz_t a, mpz_t b, mpz_t x, mpz_t y, mpz_t d) {
    mpz_t x1, x2, y1, y2, q, r, qx1, qy1, qb, a_copy, b_copy; //d=gcd
    mpz_init(a_copy);
    mpz_init(b_copy);
    mpz_set(a_copy, a);
    mpz_set(b_copy, b);
    mpz_init(x1);
    mpz_init(x2);
    mpz_init(y1);
    mpz_init(y2);
    mpz_init(r);
    mpz_init(q);
    mpz_init(qx1);
    mpz_init(qy1);
    mpz_init(qb);
    //αν b=0 τοτε d=a, x=1, y=0.
    if (mpz_cmp_ui(b_copy, 0) == 0) {
        mpz_set(d, a_copy);
        mpz_set_ui(x, 1);
        mpz_set_ui(y, 0);
        return;
    }
    //an b δεν είναι 0 τότε
    //x2=1, x1=0, y2=0, y1=1
    mpz_set_ui(x2, 1);
    mpz_set_ui(x1, 0);
    mpz_set_ui(y2, 0);
    mpz_set_ui(y1, 1);
    //όσο b>0
    while (mpz_cmp_ui(b_copy, 0) > 0) {
        //q= [a/b], fdiv κανει flooring, δηλαδη 8/5 = 1.κατι..= 1 (ενω ceil θα εβγαζε 2)
        mpz_fdiv_q(q, a_copy, b_copy);
        // r = a -qb
        mpz_mul(qb, q, b_copy);
        mpz_sub(r, a_copy, qb);
        //x = x2 -qx1
        mpz_mul(qx1, q, x);
        mpz_sub(x, x2, qx1);
        //y = y2 - qy1
        mpz_mul(qy1, q, y1);
        mpz_sub(y, y2, qy1);
        //a=b
        mpz_set(a_copy, b_copy);
        //b=r
        mpz_set(b_copy, r);
        //x2=x1
        mpz_set(x2, x1);
        //x1=x
        mpz_set(x1, x);
        //y2=y1
        mpz_set(y2, y1);
        //y1=y
        mpz_set(y1, y);
    }
    //d=a, x=x2, y=y2
    mpz_set(d, a_copy);
    mpz_set(x, x2);
    mpz_set(y, y2);
    //τα τα a,x,y έχουν τιμές

    mpz_clear(x1);
    mpz_clear(x2);
    mpz_clear(y1);
    mpz_clear(y2);
    mpz_clear(r);
    mpz_clear(q);
    mpz_clear(qx1);
    mpz_clear(qy1);
    mpz_clear(qb);
    mpz_clear(a_copy);
    mpz_clear(b_copy);
}

void CryptoRabin::e_euclid(mpz_t a, mpz_t b, mpz_t gcd_a_b) {
    mpz_init(a);
    mpz_init(b);
    mpz_init(gcd_a_b);
    mpz_cmp(p, q) > 1 ? euclid(p, q, a, b, gcd_a_b) : euclid(q, p, b, a, gcd_a_b);
}

//εύρεση 4 πιθανών plaintext από 1 rabin ciphertext
//4 πιθανά plaintext: x,  -x MOD n, y, -y MOD n
void CryptoRabin::calculate_four_candidates(mpz_t ciphertext, mpz_t a, mpz_t b, mpz_t x, mpz_t mx_mod_n, mpz_t y, mpz_t my_mod_n) {
    mpz_t r, s, mx, my, p_plus_one, p_plus_one_div4, q_plus_one, q_plus_one_div4, ap, bq, aps, bqr, aps_plus_bqr, aps_minus_bqr;
    mpz_init(x); //x
    mpz_init(mx_mod_n); // -x mod N
    mpz_init(y); //y
    mpz_init(my_mod_n); // -y mod N
    mpz_init(r);
    mpz_init(s);
    mpz_init(mx); //-x
    mpz_init(my); //-y
    mpz_init(p_plus_one);
    mpz_init(p_plus_one_div4);
    mpz_init(q_plus_one);
    mpz_init(q_plus_one_div4);
    mpz_init(ap);
    mpz_init(bq);
    mpz_init(aps);
    mpz_init(bqr);
    mpz_init(aps_plus_bqr);
    mpz_init(aps_minus_bqr);

    // r = c^((p+1)/4) MOD p
    mpz_add_ui(p_plus_one, p, 1);
    mpz_fdiv_q_ui(p_plus_one_div4, p_plus_one, 4);
    mpz_powm(r, ciphertext, p_plus_one_div4, p);

    // s = c^((q+1)/4) MOD q
    mpz_add_ui(q_plus_one, q, 1);
    mpz_fdiv_q_ui(q_plus_one_div4, q_plus_one, 4);
    mpz_powm(s, ciphertext, q_plus_one_div4, q);

    //abs, bqr
    mpz_mul(ap, a, p);
    mpz_mul(aps, ap, s);
    mpz_mul(bq, b, q);
    mpz_mul(bqr, bq, r);
    // x = (aps + bqr) MOD n (1)
    mpz_add(aps_plus_bqr, aps, bqr);
    mpz_mod(x, aps_plus_bqr, n);
    // y = (aps - bqr) MOD n (2)
    mpz_sub(aps_minus_bqr, aps, bqr);
    mpz_mod(y, aps_minus_bqr, n);

    //-x
    mpz_mul_si(mx, x, -1);
    //-y
    mpz_mul_si(my, y, -1);
    //-x mod n (3)
    mpz_mod(mx_mod_n, mx, n);
    //-y mod n (4)
    mpz_mod(my_mod_n, my, n);

    mpz_clear(p_plus_one);
    mpz_clear(p_plus_one_div4);
    mpz_clear(q_plus_one);
    mpz_clear(q_plus_one_div4);
    mpz_clear(ap);
    mpz_clear(bq);
    mpz_clear(aps);
    mpz_clear(bqr);
    mpz_clear(aps_plus_bqr);
    mpz_clear(aps_minus_bqr);
    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(mx);
    mpz_clear(my);
}

//εύρεση του σωστού plaintext
bool CryptoRabin::get_correct_plaintext(mpz_t x, mpz_t y, mpz_t mx_mod_n, mpz_t my_mod_n, mpz_t correct_plaintext) {
    //200*200bits max = 400 bits
    std::unique_ptr<char[]>x_chars(new char[400]);
    std::unique_ptr<char[]>y_chars(new char[400]);
    std::unique_ptr<char[]>mx_chars(new char[400]);
    std::unique_ptr<char[]>my_chars(new char[400]);
    //κάνουμε "dump" στους buffer arrays τους αριθμούς
    int size_x = gmp_sprintf(x_chars.get(), "%Zd", x);
    int size_y = gmp_sprintf(y_chars.get(), "%Zd", y);
    int size_mx = gmp_sprintf(mx_chars.get(), "%Zd", mx_mod_n);
    int size_my = gmp_sprintf(my_chars.get(), "%Zd", my_mod_n);
    //αν κάποιο δε διαβάστηκε σωστά τότε οι παραμέτροι είναι λάθος
    if (size_x < 0 || size_y < 0 || size_mx < 0 || size_my < 0) {
        cout << "Could not read some or all of the possible plaintexts!\n\n";
        return false;
    }

    int i;
    bool is_x = true, is_y = true, is_mx = true, is_my = true;
    //έλεγχος των 12 τελευταίων ψηφίων για κάθε buffer array: αν είναι όλα όσο το padded τότε τους αφαιρούμε
    //και επιστρέφουμε το plaintext
    for (i = size_x - 1; i >= (size_x - 1) - 11; i--) {
        if (x_chars[i] != 1 + '0') {
            is_x = false;
            break;
        }
    }
    for (i = size_y - 1; i >= (size_y - 1) - 11; i--) {
        if (y_chars[i] != 1 + '0') {
            is_y = false;
            break;
        }
    }
    for (i = size_mx - 1; i >= (size_mx - 1) - 11; i--) {
        if (mx_chars[i] != 1 + '0') {
            is_mx = false;
            break;
        }
    }
    for (i = size_my - 1; i >= (size_my - 1) - 11; i--) {
        if (my_chars[i] != 1 + '0') {
            is_my = false;
            break;
        }
    }
    if (is_x == false && is_y == false && is_mx == false && is_my == false) {
        cout << "Wrong parameters! None of the four plaintexts are correct\n\n";
        return false;
    }
    mpz_init(correct_plaintext);
    std::string buf;
    if (is_x) {
        for (i = 0; i < size_x - 12; i++)
            buf += x_chars[i];
        gmp_sscanf(buf.c_str(), "%Zd", correct_plaintext);
    }
    else if (is_y) {
        for (i = 0; i < size_y - 12; i++)
            buf += y_chars[i];
        gmp_sscanf(buf.c_str(), "%Zd", correct_plaintext);
    }
    else if (is_mx) {
        for (i = 0; i < size_mx - 12; i++)
            buf += mx_chars[i];
        gmp_sscanf(buf.c_str(), "%Zd", correct_plaintext);
    }
    else if (is_my) {
        for (i = 0; i < size_my - 12; i++)
            buf += my_chars[i];
        gmp_sscanf(buf.c_str(), "%Zd", correct_plaintext);
    }
    return true;
}
