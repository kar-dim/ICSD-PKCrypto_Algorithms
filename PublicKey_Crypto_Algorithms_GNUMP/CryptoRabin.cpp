#include "CryptoRabin.h"

void CryptoRabin::init() {
	CryptoBase::init();
	mpz_init(p);
	mpz_init(q);
	mpz_init(n);
}

void CryptoRabin::initialize_parameters() {
    //όπως και στο RSA, έτσι και εδώ θα πρέπει να βρεθούν δύο prime p,q.
    //με την ίδια ακριβώς διαδικασία τους δημιουργούμε αλλά εδώ έχουμε ένα επιπλέον βήμα
    //να ελέγξουμε αν p==q==3mod4, δηλαδή αν p MOD 4 = q MOD 4 = 3 mod 4 -> p MOD 4 = q MOD 4 = 3
    mpz_t temp_p, temp_q;
    mpz_init(temp_p);
    mpz_init(temp_q);
    //δίνουμε random τιμή και ελέγχουμε αν είναι prime
    while (true) {
        //δημιουργία των δυο τυχαίων μεγέθους 200bits
        mpz_urandomb(p, state, 200);
        mpz_urandomb(q, state, 200);
        //έλεγχος αν είναι prime, αν είναι τότε ελέγχουμε και την επιπλέον συνθήκη, αλλιώς θα ξαναδημιουργηθούν πάλι δύο τυχαίοι
        //το 30 είναι ο αριθμός των επαναλήψεων για να ελεγθεί αν είναι prime
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
    printf("p = ");
    mpz_out_str(NULL, 10, p);
    printf("\n\n");
    printf("q = ");
    mpz_out_str(NULL, 10, q);
    printf("\n\n");
    printf("n = ");
    mpz_out_str(NULL, 10, n);
    printf("\n\n");
}

bool CryptoRabin::english_to_decimal(mpz_t number, const char* word) {
    int size = (int)strlen(word);
    char* characters_as_numbers = new char[(size * 3) + 12 + 1]; //ένας τριψήφιος αριθμός είναι ένα γράμμα στο ASCII (pad με 0 μπροστά αν είναι διψήφιος)
    int i;
    for (i = 0; i < size; i++) {
        //παίρνουμε τη ASCII μορφή του χαρακτήρα
        int temp = (int)word[i];
        //αν είναι 2ψήφιος τότε βάζουμε ένα 0 μπροστά
        if (number_of_digits(temp) == 2) {
            characters_as_numbers[(i * 3)] = '0';
            characters_as_numbers[(i * 3) + 1] = get_digit(temp, 1) + '0';
            characters_as_numbers[(i * 3) + 2] = get_digit(temp, 0) + '0';
        }
        else if (number_of_digits(temp) == 3) {
            characters_as_numbers[(i * 3)] = get_digit(temp, 2) + '0';
            characters_as_numbers[(i * 3) + 1] = get_digit(temp, 1) + '0';
            characters_as_numbers[(i * 3) + 2] = get_digit(temp, 0) + '0';
        }
        else {
            printf("Not an English word, can't encrypt it!\n");
            delete[] characters_as_numbers;
            return false;
        }
    }
    //γέμισμα με δώδεκα άσους
    for (i = (size * 3); i < (size * 3) + 12; i++)
        characters_as_numbers[i] = 1 + '0';
    characters_as_numbers[(size * 3) + 12] = '\0';
    printf("Encoded characters (plus redundancy): %s\n\n", characters_as_numbers);
    //τώρα ο πίνακας characters_as_numbers περιέχει τους χαρακτήρες. Άρα για word='rsa' -> 114115097 οπότε αυτός ο αριθμός
    //είναι που θα γίνει (στη συνέχεια) η κρυπτογράφηση, οπότε τον αποθηκεύουμε με το GNUMP
    if (mpz_set_str(number, characters_as_numbers, 10) == -1) {
        printf("Failed to encode the word! Can't encrypt\n");
        delete[] characters_as_numbers;
        return false;
    }
    //αν δεν έχουμε φύγει από τη συνάρτηση σημαίνει πως όλα πήγαν καλά
    //οπότε ο mpz_t number έχει τη τιμή που θέλουμε
    delete[] characters_as_numbers;
    return true;
}

void CryptoRabin::encrypt(mpz_t plaintext, mpz_t ciphertext) {
    mpz_powm_ui(ciphertext, plaintext, 2, n);
}

//συνάρτηση που βρίσκει τα x,y ώστε ax + by = 1
//είναι ο επεκταμένος αλγόριθμος του Ευκλείδη που κάναμε για RSA, όμως τώρα θα τον χρησιμοποιήσουμε
//για να βρούμε τα x,y (θεωρούμe πως a>=b) καθώς και το gcd το οποίο πρέπει να κάνει 1.
//(απευθείας εφαρμογή του βιβλίου "Handbook of Applied Cryptography" )
void CryptoRabin::euclid(mpz_t a, mpz_t b, mpz_t x, mpz_t y, mpz_t d) {
    mpz_t x1, x2, y1, y2, q, r, qx1, qy1, qb, a_copy, b_copy; //d=gcd
    mpz_init(a_copy); //a_copy ώστε να μη πειράξουμε τον πρώτο prime
    mpz_init(b_copy); //b_copy ώστε να μη πειράξουμε τον δεύτερο prime
    mpz_set(a_copy, a); //a_copy=a και b_copy=b. Θα δουλέψουμε με τα αντίγραφα και όχι με τους a,b
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
    //έχουμε τα a,x,y οπότε τέλος
    //καθαρισμός των temp
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
    mpz_cmp(p, q) > 1 ? euclid(p, q, a, b, gcd_a_b) : euclid(q, p, b, a, gcd_a_b);
}

//έχωντας τα a,b μπορούμε να βρούμε τα 4 πιθανά plaintext
// r = c^((p+1)/4) MOD p
// s = c^((q+1)/4) MOD q
// x = (aps + bqr) MOD n
// y = (aps - bqr) MOD n
//4 πιθανά plaintext: x,  -x MOD n, y, -y MOD n
void CryptoRabin::calculate_four_candidates(mpz_t ciphertext, mpz_t a, mpz_t b, mpz_t x, mpz_t mx_mod_n, mpz_t y, mpz_t my_mod_n) {
    mpz_t r, s, mx, my, p_plus_one, p_plus_one_div4, q_plus_one, q_plus_one_div4, ap, bq, aps, bqr, aps_plus_bqr, aps_minus_bqr;
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

    //clear όλων των temp
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

bool CryptoRabin::get_correct_plaintext(mpz_t x, mpz_t y, mpz_t mx_mod_n, mpz_t my_mod_n, mpz_t correct_plaintext) {
    //ελέγχεται ένα-ένα αν έχει το redundancy που θέλουμε (δηλαδή 12 άσους στο τέλος)
    char* x_chars, * y_chars, * mx_chars, * my_chars;
    //200*200bits max =400 bits οπότε ας έχουμε 400 buffer size
    x_chars = new char[400]; 
    y_chars = new char[400];
    mx_chars = new char[400];
    my_chars = new char[400];
    //κάνουμε "dump" στους buffer arrays τους αριθμούς, κρατώντας και το πλήθος των ψηφίων που διαβάστηκαν
    //θα μας είναι χρήσιμο στο συνέχεια
    int size_x = gmp_sprintf(x_chars, "%Zd", x);
    int size_y = gmp_sprintf(y_chars, "%Zd", y);
    int size_mx = gmp_sprintf(mx_chars, "%Zd", mx_mod_n);
    int size_my = gmp_sprintf(my_chars, "%Zd", my_mod_n);
    //αν κάποιο δε διαβάστηκε σωστά τότε οι παραμέτροι είναι λάθος
    if (size_x < 0 || size_y < 0 || size_mx < 0 || size_my < 0) {
        printf("Could not read some or all of the possible plaintexts!\n\n");
        delete[] x_chars;
        delete[] y_chars;
        delete[] mx_chars;
        delete[] my_chars;
        return false;
    }

    int i;
    bool is_x = true, is_y = true, is_mx = true, is_my = true;
    //έλεγχος των 12 τελευταίων ψηφίων για κάθε buffer array: αν είναι όλα άσοι τότε τους αφαιρούμε
    //και επιστρέφουμε το αποτέλεσμα
    for (i = size_x - 1; i >= (size_x - 1) - 11; i--) {
        //αν έστω ένας δεν είναι '1' τότε δεν είναι το σωστό plaintext
        if (x_chars[i] != 1 + '0') {
            is_x = false;
            break;
        }
    }
    for (i = size_y - 1; i >= (size_y - 1) - 11; i--) {
        //αν έστω ένας δεν είναι '1' τότε δεν είναι το σωστό plaintext
        if (y_chars[i] != 1 + '0') {
            is_y = false;
            break;
        }
    }
    for (i = size_mx - 1; i >= (size_mx - 1) - 11; i--) {
        //αν έστω ένας δεν είναι '1' τότε δεν είναι το σωστό plaintext
        if (mx_chars[i] != 1 + '0') {
            is_mx = false;
            break;
        }
    }
    for (i = size_my - 1; i >= (size_my - 1) - 11; i--) {
        //αν έστω ένας δεν είναι '1' τότε δεν είναι το σωστό plaintext
        if (my_chars[i] != 1 + '0') {
            is_my = false;
            break;
        }
    }
    //πρέπει μόνο ένα boolean να είναι true, αν δε βρέθηκε κανένα τότε δεν έχουμε σωστούς παραμέτρους
    if (is_x == false && is_y == false && is_mx == false && is_my == false) {
        printf("Wrong parameters! None of the four plaintexts are correct\n\n");
        delete[] x_chars;
        delete[] y_chars;
        delete[] mx_chars;
        delete[] my_chars;
        return false;
    }
    //απλώς αφαιρούμε τα 12 τελευταία ψηφία και αποθηκέυουμε τον αριθμό στο correct_plaintext
    char* buf;
    if (is_x) {
        buf = new char[size_x - 12 + 1];
        for (i = 0; i < size_x - 12; i++) {
            buf[i] = x_chars[i];
        }
        buf[size_x - 12] = '\0';
        //πετάμε από το buf το οποίο έχει το plaintext χωρίς redundancy στο correct_plaintext
        gmp_sscanf(buf, "%Zd", correct_plaintext);
    }
    else if (is_y) {
        buf = new char[size_y - 12 + 1];
        for (i = 0; i < size_y - 12; i++) {
            buf[i] = y_chars[i];
        }
        buf[size_y - 12] = '\0';
        //πετάμε από το buf το οποίο έχει το plaintext χωρίς redundancy στο correct_plaintext
        gmp_sscanf(buf, "%Zd", correct_plaintext);
    }
    else if (is_mx) {
        buf = new char[size_mx - 12 + 1];
        for (i = 0; i < size_mx - 12; i++) {
            buf[i] = mx_chars[i];
        }
        buf[size_mx - 12] = '\0';
        //πετάμε από το buf το οποίο έχει το plaintext χωρίς redundancy στο correct_plaintext
        gmp_sscanf(buf, "%Zd", correct_plaintext);
    }
    else if (is_my) {
        buf = new char[size_mx - 12 + 1];
        for (i = 0; i < size_my - 12; i++) {
            buf[i] = my_chars[i];
        }
        buf[size_my - 12] = '\0';
        //πετάμε από το buf το οποίο έχει το plaintext χωρίς redundancy στο correct_plaintext
        gmp_sscanf(buf, "%Zd", correct_plaintext);
    }
    //free τον χώρο που δεσμεύτηκε
    delete[] x_chars;
    delete[] y_chars;
    delete[] mx_chars;
    delete[] my_chars;
    delete[] buf;
    return true;
}
