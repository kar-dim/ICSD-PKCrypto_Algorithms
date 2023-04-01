#include <time.h>
#include "CryptoRSA.h"
#include "CryptoElGamal.h"
#include "CryptoRabin.h"
#include <string>
#include <iostream>

using std::cout;

int main(int argc, char** argv) {

    if (argc != 3) {
        cout << "No Crypto method or input text found, exiting";
        return -1;
    }

    std::string crypto_method(argv[1]);
    std::string input(argv[2]);

    if (crypto_method.compare("rsa") == 0) {
        CryptoRSA rsa;
        rsa.init();

        //τώρα θα φτιάξουμε τους παραμέτρους, δηλαδή το p,q n και totient (phi)
        rsa.initialize_parameters();
        //εκτύπωση των παραμέτρων
        rsa.print_parameters();

        //private key: (d,n) όπου d βρίσκεται ως: e*d = 1 mod (φ(n))
        //θα χρησιμοποιήσουμε τον επεκταμένο αλγόριθμο του Ευκλείδη για να βρούμε το d
        rsa.e_euclid();
        rsa.print_private_key();

        //θα εξετάσουμε το string "rsa"
        cout << "Plaintext message = " << input << "\n\n";

        mpz_t rsa_decimal_value;
        mpz_init(rsa_decimal_value);
        rsa.english_to_decimal(rsa_decimal_value, input);

        //έχουμε στο rsa_decimal_value έναν ακέραιο, οπότε μπορούμε να κρυπτογραφήσουμε με το public key.
        //κρυπτογραφημένο Ciphertext στον RSA είναι το εξής: C = m^e mod n, m=rsa_decimal_value, e=65537
        mpz_t ciphertext;
        rsa.encrypt(rsa_decimal_value, ciphertext);

        //εκτύπωση του ciphertext
        cout << "Encrypted Ciphertext = ";
        mpz_out_str(NULL, 10, ciphertext);
        cout << "\n\n";

        //τώρα θα πάρουμε το ciphertext και θα κάνουμε την αποκρυπτογράφηση. Η πράξη της αποκρυπτογράφησης είναι:
        //m = c^d MOD n, c=ciphertext, d=private key, m=plaintext, άρα παρόμοια έχουμε:
        mpz_t plaintext;
        rsa.decrypt(plaintext, ciphertext);

        //εκτύπωση του plaintext, πρέπει να είναι ακριβώς ίδιο με το (encoded) μήνυμα.
        cout << "Decrypted (and encoded) Plaintext = ";
        mpz_out_str(NULL, 10, plaintext);
        cout << "\n\n";

        //η αποκρυπτογράφηση έχει τελειώσει, εδώ απλώς κάνουμε decode (από αριθμό σε string το μήνυμα)
        std::string decoded;
        rsa.decimal_to_english(plaintext, decoded, 1024);

        cout << "Decoded plaintext = " << decoded;
        return 0;
    }

    if (crypto_method.compare("elgamal") == 0) {
        CryptoElGamal elgamal;
        elgamal.init();

        elgamal.initialize_parameters();
        elgamal.print_parameters();

        //θα κρυπτογραφήσουμε το κείμενο
        cout << "Plaintext message = " << input << "\n\n";

        mpz_t elgamal_decimal_value;
        mpz_init(elgamal_decimal_value);
        elgamal.english_to_decimal(elgamal_decimal_value, input);

        //τώρα θα γίνει η κρυπτογράφηση
        mpz_t c1, c2;
        mpz_init(c1);
        mpz_init(c2);
        elgamal.encrypt(elgamal_decimal_value,c1, c2);

        //εκτύπωση των δύο ciphertext
        cout << "Encrypted Ciphertext c1 = ";
        mpz_out_str(NULL, 10, c1);
        cout << "\n\n";
        cout << "Encrypted Ciphertext c2 = ";
        mpz_out_str(NULL, 10, c2);
        cout << "\n\n";

        //τώρα θα κάνουμε την αποκρυπτογράφηση
        mpz_t decrypted;
        mpz_init(decrypted);
        elgamal.decrypt(c1, c2, decrypted);

        //εκτύπωση, θα πρέπει να εκτυπώνεται ό,τι εκτυπώθηκε και πριν ως encoded plaintext
        cout << "Decrypted (and encoded) plaintext = ";
        mpz_out_str(NULL, 10, decrypted);
        cout << "\n\n";

        //η αποκρυπτογράφηση έχει τελειώσει, εδώ απλώς κάνουμε decode (από αριθμό σε string το μήνυμα)
        std::string decoded;
        elgamal.decimal_to_english(decrypted, decoded, 200);

        cout << "Decoded plaintext = " << decoded;

        return 0;
    }

    if (crypto_method.compare("rabin") == 0) {
        CryptoRabin rabin;
        rabin.init();

        rabin.initialize_parameters();
        rabin.print_parameters();

        cout << "Plaintext message = " << input << "\n\n";
        mpz_t rabin_decimal_value;
        mpz_init(rabin_decimal_value);
        rabin.english_to_decimal(rabin_decimal_value, input);


        //κρυπτογράφηση
        mpz_t ciphertext;
        mpz_init(ciphertext);
        rabin.encrypt(rabin_decimal_value, ciphertext);
        cout << "Encrypted Ciphertext = ";
        mpz_out_str(NULL, 10, ciphertext);
        cout << "\n\n";

        //τώρα θα αποκρυπτογραφήσουμε
        //πρώτα υπολογίζουμε τα a,b που χρειάζονται. Αυτά υπολογίζονται μόνο μια φορά
        mpz_t a, b, gcd_a_b;
        mpz_init(a);
        mpz_init(b);
        mpz_init(gcd_a_b);
        //καλούμε τον επεκταμένο αλγόριθμο του ευκλείδη για να βρούμε τα a,b
        //επειδή θεωρούμε πως η 1η παράμετρος είναι >= της 2ης, θα δώσουμε ως πρώτη παράμετρο τον μεγαλύτερο (προφανώς αντίστοιχα και τα a,b)
        rabin.e_euclid(a, b, gcd_a_b);

        //εκτύπωση των a,b και του gcd(a,b)=1
        cout << "a = ";
        mpz_out_str(NULL, 10, a);
        cout << "\n\n";
        cout << "b = ";
        mpz_out_str(NULL, 10, b);
        cout << "\n\n";
        cout << "d (MUST BE 1) = ";
        mpz_out_str(NULL, 10, gcd_a_b);
        cout << "\n\n";
        //αν gcd(a,b) δεν είναι 1 τότε σφάλμα
        if (mpz_cmp_ui(gcd_a_b, 1) != 0) {
            cout << "Error trying to initialize the decryption process! Exiting...";
            return -1;
        }

        //ευρεση των 4 πιθανων plaintexts
        mpz_t x, y, mx_mod_n, my_mod_n;
        mpz_init(x); //x
        mpz_init(y); //y
        mpz_init(mx_mod_n); //-x mod n
        mpz_init(my_mod_n); //-y mod n
        //υπολογίζουμε τα r,s,x,y
        rabin.calculate_four_candidates(ciphertext, a, b, x, mx_mod_n, y, my_mod_n);

        //εκτυπώνουμε τα 4 πιθανά plaintext (encoded). Ένα μόνο από αυτά είναι το σωστό
        cout << "1)x = ";
        mpz_out_str(NULL, 10, x);
        cout << "\n\n";
        cout << "2)y = ";
        mpz_out_str(NULL, 10, y);
        cout << "\n\n";
        cout << "3)-x MOD n = ";
        mpz_out_str(NULL, 10, mx_mod_n);
        cout << "\n\n";
        cout << "3)-y MOD n = ";
        mpz_out_str(NULL, 10, my_mod_n);
        cout << "\n\n";

        //τώρα πρέπει να βρούμε ποιό από τα 4 είναι το σωστό και τέλος να το κάνουμε decode.
        //ελέγχουμε τα 12 τελευταία στοιχεία, αν είναι '1' όλα τότε αυτό το plaintext θέλουμε και τα κόβουμε για να πάρουμε το αρχικό plaintext
        //χωρίς το redundancy
        mpz_t correct_plaintext;
        mpz_init(correct_plaintext);
        if (!rabin.get_correct_plaintext(x, y, mx_mod_n, my_mod_n, correct_plaintext))
            return -1;

        //decode το plaintext και τέλος
        std::string decoded_word;
        rabin.decimal_to_english(correct_plaintext, decoded_word, 1024);

        //εκτύπωση του plaintext
        cout << "Decrypted and decoded (no redundancy) plaintext: " << decoded_word;

        return 0;
    }

    else {
        cout << "Wrong crypto method. Only 'rsa','elgamal' and 'rabin' allowed";
        return -1;
    }
}

