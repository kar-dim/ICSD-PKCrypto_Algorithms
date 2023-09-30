#include "CryptoRabin.h"
#include <string>
#include <gmp.h>
#include <iostream>

using std::cout;

void CryptoRabin::initialize_parameters() {
    //ευρεση δυο prime p,q ωστε p==q==3mod4, δηλαδή αν p MOD 4 = q MOD 4 = 3 mod 4 -> p MOD 4 = q MOD 4 = 3
    gmp::Mpz temp_p, temp_q;
    while (true) {
        //δημιουργία των δυο τυχαίων μεγέθους 200bits
        p.Mpz_urandomb(state, 200);
        q.Mpz_urandomb(state, 200);
        //έλεγχος αν είναι prime, αν είναι τότε ελέγχουμε και την επιπλέον συνθήκη, αλλιώς θα ξαναδημιουργηθούν πάλι δύο τυχαίοι
        if (p.Mpz_probab_prime_p(30) >= 1 && q.Mpz_probab_prime_p(30) >= 1) {
            temp_p.Mpz_mod_ui(p, 4);
            temp_q.Mpz_mod_ui(q, 4);
            //εναλλακτικά μπορούσαμε με τη συνάρτηση mpz_congruent_p_ui_p απευθείας
            //έλεγχος αν είναι ίδια και ίσα με 3
            if (temp_p.Mpz_cmp_ui(3)== 0 && temp_q.Mpz_cmp_ui(3) == 0)
                break;
        }
    }
    //εφόσον p,q είναι prime μπορούμε να υπολογίσουμε το n=pq
    n.Mpz_mul(p, q);
}

void CryptoRabin::print_parameters() {
    cout << "p = ";
    p.Mpz_out_str();
    cout << "\n\nq = ";
    q.Mpz_out_str();
    cout << "\n\nn = ";
    n.Mpz_out_str();
    cout << "\n\n";
}


bool CryptoRabin::english_to_decimal(gmp::Mpz &number, const std::string &word) {
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
    if (number.Mpz_set_str(characters_as_numbers.c_str()) == -1) {
        cout << "Failed to encode the word! Can't encrypt\n";
        return false;
    }
    return true;
}

void CryptoRabin::encrypt(const gmp::Mpz &plaintext, gmp::Mpz &ciphertext) {
    ciphertext.Mpz_powm_ui(plaintext, 2, n);
}

//επεκταμένος αλγόριθμος του Ευκλείδη που βρίσκει τα x,y ώστε ax + by = 1
//(απευθείας εφαρμογή του βιβλίου "Handbook of Applied Cryptography" )
void CryptoRabin::euclid(gmp::Mpz &a, gmp::Mpz& b, gmp::Mpz& x, gmp::Mpz& y, gmp::Mpz& d) {
    gmp::Mpz x1, x2, y1, y2, q, r, qx1, qy1, qb;
    gmp::Mpz a_copy(a), b_copy(b);

    //αν b=0 τοτε d=a, x=1, y=0.
    if (b_copy.Mpz_cmp_ui(0) == 0) {
        d = a_copy; //mpz_set(d, a_copy);
        x.Mpz_set_ui(1);
        y.Mpz_set_ui(0);
        return;
    }
    //an b δεν είναι 0 τότε
    //x2=1, x1=0, y2=0, y1=1
    x2.Mpz_set_ui(1);
    x1.Mpz_set_ui(0);
    y2.Mpz_set_ui(0);
    y1.Mpz_set_ui(1);

    //όσο b>0
    while (b_copy.Mpz_cmp_ui(0) > 0) {
        //q= [a/b], fdiv κανει flooring, δηλαδη 8/5 = 1.κατι..= 1 (ενω ceil θα εβγαζε 2)
        q.Mpz_fdiv_q(a_copy, b_copy);
        // r = a -qb
        qb.Mpz_mul(q, b_copy);
        r.Mpz_sub(a_copy, qb);
        //x = x2 -qx1
        qx1.Mpz_mul(q, x);
        x.Mpz_sub(x2, qx1);
        //y = y2 - qy1
        qy1.Mpz_mul(q, y1);
        y.Mpz_sub(y2, qy1);
        //a=b
        a_copy = b_copy;
        //mpz_set(a_copy, b_copy);
        //b=r
        b_copy = r;
        //mpz_set(b_copy, r);
        //x2=x1
        x2 = x1;
        //mpz_set(x2, x1);
        //x1=x
        x1 = x;
        //mpz_set(x1, x);
        //y2=y1
        y2 = y1;
        //mpz_set(y2, y1);
        //y1=y
        y1 = y;
        //mpz_set(y1, y);
    }
    //d=a, x=x2, y=y2
    d = a_copy;
    x = x2;
    y = y2;
    //mpz_set(d, a_copy);
    //mpz_set(x, x2);
    //mpz_set(y, y2);
    //τα τα d,x,y έχουν τιμές
}

void CryptoRabin::e_euclid(gmp::Mpz& a, gmp::Mpz& b, gmp::Mpz& gcd_a_b) {
    p.Mpz_cmp(q) > 1 ? euclid(p, q, a, b, gcd_a_b) : euclid(q, p, b, a, gcd_a_b);
}

//εύρεση 4 πιθανών plaintext από 1 rabin ciphertext
//4 πιθανά plaintext: x,  -x MOD n, y, -y MOD n
void CryptoRabin::calculate_four_candidates(const gmp::Mpz& ciphertext, const gmp::Mpz& a, const gmp::Mpz& b, gmp::Mpz& x, gmp::Mpz& mx_mod_n, gmp::Mpz& y, gmp::Mpz& my_mod_n) {
    gmp::Mpz r, s, mx, my, p_plus_one, p_plus_one_div4, q_plus_one, q_plus_one_div4, ap, bq, aps, bqr, aps_plus_bqr, aps_minus_bqr;

    // r = c^((p+1)/4) MOD p
    p_plus_one.Mpz_add_ui(p, 1);
    p_plus_one_div4.Mpz_fdiv_q_ui(p_plus_one, 4);
    r.Mpz_powm(ciphertext, p_plus_one_div4, p);

    // s = c^((q+1)/4) MOD q
    q_plus_one.Mpz_add_ui(q, 1);
    q_plus_one_div4.Mpz_fdiv_q_ui(q_plus_one, 4);
    s.Mpz_powm(ciphertext, q_plus_one_div4, q);

    //abs, bqr
    ap.Mpz_mul(a, p);
    aps.Mpz_mul(ap, s);
    bq.Mpz_mul(b, q);
    bqr.Mpz_mul(bq, r);

    // x = (aps + bqr) MOD n (1)
    aps_plus_bqr.Mpz_add(aps, bqr);
    x.Mpz_mod(aps_plus_bqr, n);
    // y = (aps - bqr) MOD n (2)
    aps_minus_bqr.Mpz_sub(aps, bqr);
    y.Mpz_mod(aps_minus_bqr, n);

    //-x
    mx.Mpz_mul_si(x, -1);
    //-y
    my.Mpz_mul_si(y, -1);
    //-x mod n (3)
    mx_mod_n.Mpz_mod(mx, n);
    //-y mod n (4)
    my_mod_n.Mpz_mod(my, n);
}

//εύρεση του σωστού plaintext

bool CryptoRabin::get_correct_plaintext(const gmp::Mpz& x, const gmp::Mpz& y, const gmp::Mpz& mx_mod_n, const gmp::Mpz& my_mod_n, gmp::Mpz& correct_plaintext) {
    //200*200bits max = 400 bits
    std::unique_ptr<char[]>x_chars(new char[400]);
    std::unique_ptr<char[]>y_chars(new char[400]);
    std::unique_ptr<char[]>mx_chars(new char[400]);
    std::unique_ptr<char[]>my_chars(new char[400]);
    //κάνουμε "dump" στους buffer arrays τους αριθμούς
    int size_x = x.sprintf(x_chars.get(), "%Zd");
    int size_y = y.sprintf(y_chars.get(), "%Zd");
    int size_mx = mx_mod_n.sprintf(mx_chars.get(), "%Zd");
    int size_my = my_mod_n.sprintf(my_chars.get(), "%Zd");

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

    std::string buf;
    if (is_x) {
        for (i = 0; i < size_x - 12; i++)
            buf += x_chars[i];
    }
    else if (is_y) {
        for (i = 0; i < size_y - 12; i++)
            buf += y_chars[i];
    }
    else if (is_mx) {
        for (i = 0; i < size_mx - 12; i++)
            buf += mx_chars[i];
    }
    else if (is_my) {
        for (i = 0; i < size_my - 12; i++)
            buf += my_chars[i];
    }
    correct_plaintext.sscanf(buf.c_str(), "%Zd");
    return true;
}
