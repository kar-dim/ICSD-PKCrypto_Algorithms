#include "CryptoRabin.h"
#include "Mpz.h"
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

using std::cout;
using std::string;
using gmp::Mpz;

CryptoRabin::CryptoRabin()
{
    //ευρεση δυο prime p,q ωστε p==q==3mod4, δηλαδή αν p MOD 4 = q MOD 4 = 3 mod 4 -> p MOD 4 = q MOD 4 = 3
    while (true) {
        p = Mpz::urandomb(state, key_factors_max_size);
        q = Mpz::urandomb(state, key_factors_max_size);
        if (Mpz::probab_prime_p(p, 30) >= 1 && Mpz::probab_prime_p(q, 30) >= 1) {
            if ((p % 4 == 3) && (q % 4 == 3))
                break;
        }
    }
    //εφόσον p,q είναι prime μπορούμε να υπολογίσουμε το n=pq
    n = p * q;
    public_key_size = n.size_in_bits();
}

void CryptoRabin::print_parameters() const {
    cout << "p = " << p << "\n\n" << "q = " << q << "\n\n" << "n = " << n << "\n\n";
}

Mpz CryptoRabin::english_to_decimal(const string &word) const {
    string characters_as_numbers = CryptoBase::english_to_decimal_str(word);
    return characters_as_numbers.empty() ? Mpz() : Mpz(characters_as_numbers + "111111111111");
}

bool CryptoRabin::encrypt(const Mpz &plaintext, Mpz ciphertexts[]) {
    if (plaintext.size_in_bits() > public_key_size - 1)
        return false;
    ciphertexts[0] = Mpz::powm_ui(plaintext, 2, n);
    return true;
}

Mpz CryptoRabin::decrypt(const Mpz ciphertexts[]) {
    Mpz a, b, gcd_a_b;
    e_euclid(a, b, gcd_a_b);
    //εκτύπωση των a,b και του gcd(a,b)=1
    cout << "a = " << a << "\n\n";
    cout << "b = " << b << "\n\n";
    cout << "d (MUST BE 1) = " << gcd_a_b << "\n\n";
    //αν gcd(a,b) δεν είναι 1 τότε σφάλμα
    if (gcd_a_b != 1)
        return Mpz();

    //ευρεση των 4 πιθανων plaintexts
    Mpz x, y, mx_mod_n, my_mod_n;
    //υπολογίζουμε τα r,s,x,y
    calculate_four_candidates(ciphertexts[0], a, b, x, mx_mod_n, y, my_mod_n);

    //εκτυπώνουμε τα 4 πιθανά plaintext (encoded). Ένα μόνο από αυτά είναι το σωστό
    cout << "1) x = " << x << "\n\n";
    cout << "2) y = " << y << "\n\n";
    cout << "3) -x MOD n = " << mx_mod_n << "\n\n";
    cout << "4) -y MOD n = " << my_mod_n << "\n\n";
    //βρίσκουμε ποιό από τα 4 είναι το σωστό (αν δε βρεθει επιστρεφεται empty Mpz)
    return get_correct_plaintext(x, y, mx_mod_n, my_mod_n);
}

//επεκταμένος αλγόριθμος του Ευκλείδη που βρίσκει τα x,y ώστε ax + by = 1
//(απευθείας εφαρμογή του βιβλίου "Handbook of Applied Cryptography" )
void CryptoRabin::euclid(const Mpz &a, const Mpz& b, Mpz& x, Mpz& y, Mpz& d) const {
    Mpz x1, x2, y1, y2, q, r, qx1, qy1, qb;
    Mpz a_copy(a), b_copy(b);

    //αν b=0 τοτε d=a, x=1, y=0.
    if (b_copy == 0) {
        d = a_copy;
        x = 1;
        y = 0;
        return;
    }

    x2 = 1, x1 = 0, y2 = 0, y1 = 1;
    while (b_copy > 0) {
        //q= [a/b], fdiv κανει flooring, δηλαδη 8/5 = 1.κατι..= 1 (ενω ceil θα εβγαζε 2)
        q = a_copy / b_copy;
        // r = a -qb
        r = a_copy - (q * b_copy);
        //x = x2 -qx1
        x = x2 - (q * x1);
        y = y2 - (q * y1);
        a_copy = b_copy;
        b_copy = r;
        x2 = x1;
        x1 = x;
        y2 = y1;
        y1 = y;
    }
    d = a_copy;
    x = x2;
    y = y2;
}

void CryptoRabin::e_euclid(Mpz& a, Mpz& b, Mpz& gcd_a_b) const {
    p > q ? euclid(p, q, a, b, gcd_a_b) : euclid(q, p, b, a, gcd_a_b);
}

//εύρεση 4 πιθανών plaintext από 1 rabin ciphertext
//4 πιθανά plaintext: x,  -x MOD n, y, -y MOD n
void CryptoRabin::calculate_four_candidates(const Mpz& ciphertext, const Mpz& a, const Mpz& b, Mpz& x, Mpz& mx_mod_n, Mpz& y, Mpz& my_mod_n) const {
    Mpz r, s, mx, my, p_plus_one, p_plus_one_div4, q_plus_one, q_plus_one_div4, ap, bq, aps, bqr, aps_plus_bqr, aps_minus_bqr;
    // r = c^((p+1)/4) MOD p
    r = Mpz::powm(ciphertext, (p + 1) / 4, p);
    // s = c^((q+1)/4) MOD q
    s = Mpz::powm(ciphertext, (q + 1) / 4, q);
    //aps, bqr
    aps = a * p * s;
    bqr = b * q * r;
    // x = (aps + bqr) MOD n (1)
    x = (aps + bqr) % n;
    // y = (aps - bqr) MOD n (2)
    y = (aps - bqr) % n;
    //-x mod n (3)
    mx_mod_n = -x % n;
    //-y mod n (4)
    my_mod_n = -y % n;
}

//βοηθητική μέθοδος για έλεγχο των decrypted plaintext
bool CryptoRabin::check_plaintext_chars(const std::unique_ptr<char[]>& chars, const int size) const {
    return std::memcmp(chars.get() + size - 12, "11111111111", 11) == 0;
}
//βοηθητική μέθοδος για να γεμισει το τελικο plaintext με βαση το decrypted plaintext (αν ειναι το σωστο, αλλιως δεν κανει τιποτα)
void CryptoRabin::check_and_retrieve_plaintext(const bool is_correct, const std::unique_ptr<char[]>& chars, const size_t size, string &buf) const {
    if (is_correct)
       buf.append(chars.get(), size - 12);
}

//εύρεση του σωστού plaintext
Mpz CryptoRabin::get_correct_plaintext(const Mpz& x, const Mpz& y, const Mpz& mx_mod_n, const Mpz& my_mod_n) const {
    //x*x max = 2x bits
    const int max_size = key_factors_max_size * 2;
    std::unique_ptr<char[]>x_chars(new char[max_size]);
    std::unique_ptr<char[]>y_chars(new char[max_size]);
    std::unique_ptr<char[]>mx_chars(new char[max_size]);
    std::unique_ptr<char[]>my_chars(new char[max_size]);
    //κάνουμε "dump" στους buffer arrays τους αριθμούς
    int size_x = x.sprintf(x_chars.get(), "%Zd");
    int size_y = y.sprintf(y_chars.get(), "%Zd");
    int size_mx = mx_mod_n.sprintf(mx_chars.get(), "%Zd");
    int size_my = my_mod_n.sprintf(my_chars.get(), "%Zd");

    //αν κάποιο δε διαβάστηκε σωστά τότε οι παραμέτροι είναι λάθος
    if (size_x < 0 || size_y < 0 || size_mx < 0 || size_my < 0)
        return Mpz();

    //έλεγχος των 12 τελευταίων ψηφίων για κάθε buffer array: αν είναι όλα όσο το padded τότε τους αφαιρούμε
    //και επιστρέφουμε το plaintext
    const bool is_x = check_plaintext_chars(x_chars, size_x);
    const bool is_y = check_plaintext_chars(y_chars, size_y);
    const bool is_mx = check_plaintext_chars(mx_chars, size_mx);
    const bool is_my = check_plaintext_chars(my_chars, size_my);

    if (is_x == false && is_y == false && is_mx == false && is_my == false)
        return Mpz();

    string buf;
    check_and_retrieve_plaintext(is_x, x_chars, size_x, buf);
    check_and_retrieve_plaintext(is_y, y_chars, size_y, buf);
    check_and_retrieve_plaintext(is_mx, mx_chars, size_mx, buf);
    check_and_retrieve_plaintext(is_my, my_chars, size_my, buf);
    
    Mpz correct_plaintext;
    correct_plaintext.sscanf(buf.c_str(), "%Zd");
    return correct_plaintext;
}
