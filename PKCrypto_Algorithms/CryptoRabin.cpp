#include "CryptoBase.h"
#include "CryptoRabin.h"
#include "Mpz.h"
#include <array>
#include <iostream>
#include <string>
#include <vector>

using std::cout;
using std::string;
using gmp::Mpz;

const Mpz CryptoRabin::redundancy = Mpz("11111111111");
const Mpz CryptoRabin::redundancy_factor = Mpz::pow_ui(10, static_cast<ulong>(redundancy.size_in_base(10)));

CryptoRabin::CryptoRabin() : CryptoBase()
{
    //ευρεση δυο prime p,q ωστε p==q==3mod4, δηλαδή αν p MOD 4 = q MOD 4 = 3 mod 4 -> p MOD 4 = q MOD 4 = 3
    while (true) {
        p = Mpz::urandomb(state, key_factors_max_size);
        q = Mpz::urandomb(state, key_factors_max_size);
        if (Mpz::probab_prime_p(p, 30) >= 1 && Mpz::probab_prime_p(q, 30) >= 1)
            if ((p % 4 == 3) && (q % 4 == 3) && (euclid(p, q, a_p, b_q) == 1))
                break;
    }
    //εφόσον p,q είναι prime μπορούμε να υπολογίσουμε το n=pq
    n = p * q;
    public_key_size = n.size_in_base(2);
}

//constructor για αρχικοποίηση με σταθερά p,q (κυρίως για test)
CryptoRabin::CryptoRabin(const Mpz& p, const Mpz& q) : CryptoBase(), p(p), q(q), n(p * q) { 
    public_key_size = n.size_in_base(2); 
    euclid(p, q, a_p, b_q);
}

void CryptoRabin::print_parameters() const {
    cout << "p = " << p << "\n\n" << "q = " << q << "\n\n" << "n = " << n << "\n\n";
}

Mpz CryptoRabin::english_to_decimal(const string &word) const {
	Mpz encoded = CryptoBase::english_to_decimal(word);
    encoded *= redundancy_factor;
    encoded += redundancy;
    return encoded;
}

bool CryptoRabin::encrypt(const Mpz &plaintext, std::vector<Mpz>& ciphertext) {
   if (plaintext >= n || Mpz::gcd(plaintext, n) != 1)
        return false;
    ciphertext[0] = Mpz::powm_ui(plaintext, 2, n);
    return true;
}

Mpz CryptoRabin::decrypt(const std::vector<Mpz>& ciphertext) {
    //ευρεση των 4 πιθανων plaintexts
	std::array<Mpz, 4> candidates;
    //υπολογίζουμε τα r,s,x,y
    calculate_candidates(ciphertext[0], candidates);
    //εκτυπώνουμε τα 4 πιθανά plaintext (encoded). Ένα μόνο από αυτά είναι το σωστό
    cout << "1) x = " << candidates[0] << "\n\n";
    cout << "2) y = " << candidates[1] << "\n\n";
    cout << "3) -x MOD n = " << candidates[2] << "\n\n";
    cout << "4) -y MOD n = " << candidates[3] << "\n\n";
    //βρίσκουμε ποιό από τα 4 είναι το σωστό (αν δε βρεθει επιστρεφεται empty Mpz)
    return get_correct_plaintext(candidates);
}

//επεκταμένος αλγόριθμος του Ευκλείδη που βρίσκει τα x,y ώστε ax + by = 1
//(απευθείας εφαρμογή του βιβλίου "Handbook of Applied Cryptography" )
Mpz CryptoRabin::euclid(const Mpz &a, const Mpz& b, Mpz& x, Mpz& y) const {
    Mpz x1, x2, y1, y2, q, r, qx1, qy1, qb, d;
    Mpz a_copy(a), b_copy(b);

    //αν b=0 τοτε d=a, x=1, y=0.
    if (b_copy == 0) {
        d = a_copy;
        x = 1;
        y = 0;
        return d;
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
    return d;
}

//εύρεση 4 πιθανών plaintext από 1 rabin ciphertext
//4 πιθανά plaintext: x,  -x MOD n, y, -y MOD n
void CryptoRabin::calculate_candidates(const Mpz& ciphertext, std::array<Mpz, 4>& candidates) const {
    Mpz r, s, mx, my, p_plus_one, p_plus_one_div4, q_plus_one, q_plus_one_div4, ap, bq, aps, bqr, aps_plus_bqr, aps_minus_bqr;
    // r = c^((p+1)/4) MOD p
    r = Mpz::powm(ciphertext, (p + 1) / 4, p);
    // s = c^((q+1)/4) MOD q
    s = Mpz::powm(ciphertext, (q + 1) / 4, q);
    //aps, bqr
    aps = a_p * p * s;
    bqr = b_q * q * r;
    // x = (aps + bqr) MOD n (1)
	candidates[0] = (aps + bqr) % n;
    // y = (aps - bqr) MOD n (2)
	candidates[1] = (aps - bqr) % n;
    //-x mod n (3)
	candidates[2] = -candidates[0] % n;
    //-y mod n (4)
	candidates[3] = -candidates[1] % n;
}

//εύρεση του σωστού plaintext
Mpz CryptoRabin::get_correct_plaintext(const std::array<Mpz, 4>& candidates) const {
    for (const auto& candidate : candidates) {
        if (candidate % redundancy_factor == redundancy)
            return candidate / redundancy_factor;
    }
    return Mpz();
}
