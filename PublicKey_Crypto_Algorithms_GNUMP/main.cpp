#include <time.h>
#include "CryptoRSA.h"
#include "CryptoElGamal.h"
#include "CryptoRabin.h"
#include <string.h>

int main(int argc, char** argv) {

    if (argc != 3) {
        printf("No Crypto method or input text found, exiting");
        return -1;
    }

    const char* crypto_method = argv[1];
    const char* input = argv[2];

    if (strcmp("rsa", crypto_method) == 0) {
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
        printf("Plaintext message = %s\n\n", input);

        mpz_t rsa_decimal_value;
        mpz_init(rsa_decimal_value);
        rsa.english_to_decimal(rsa_decimal_value, input);

        //έχουμε στο rsa_decimal_value έναν ακέραιο, οπότε μπορούμε να κρυπτογραφήσουμε με το public key.
        //κρυπτογραφημένο Ciphertext στον RSA είναι το εξής: C = m^e mod n, m=rsa_decimal_value, e=65537
        mpz_t ciphertext;
        rsa.encrypt(rsa_decimal_value, ciphertext);

        //εκτύπωση του ciphertext
        printf("Encrypted Ciphertext = ");
        mpz_out_str(NULL, 10, ciphertext);
        printf("\n\n");

        //τώρα θα πάρουμε το ciphertext και θα κάνουμε την αποκρυπτογράφηση. Η πράξη της αποκρυπτογράφησης είναι:
        //m = c^d MOD n, c=ciphertext, d=private key, m=plaintext, άρα παρόμοια έχουμε:
        mpz_t plaintext;
        rsa.decrypt(plaintext, ciphertext);

        //εκτύπωση του plaintext, πρέπει να είναι ακριβώς ίδιο με το (encoded) μήνυμα.
        printf("Decrypted (and encoded) Plaintext = ");
        mpz_out_str(NULL, 10, plaintext);
        printf("\n\n");

        //η αποκρυπτογράφηση έχει τελειώσει, εδώ απλώς κάνουμε decode (από αριθμό σε string το μήνυμα)
        char* decoded;
        rsa.decimal_to_english(plaintext, &decoded, 1024);

        printf("Decoded plaintext = %s", decoded);

        delete[] decoded;
        return 0;
    }

    else if (strcmp("elgamal", crypto_method) == 0) {
        CryptoElGamal elgamal;
        elgamal.init();

        elgamal.initialize_parameters();
        elgamal.print_parameters();

        //θα κρυπτογραφήσουμε το κείμενο
        printf("Plaintext message = %s\n\n", input);

        mpz_t elgamal_decimal_value;
        mpz_init(elgamal_decimal_value);
        elgamal.english_to_decimal(elgamal_decimal_value, input);

        //τώρα θα γίνει η κρυπτογράφηση
        mpz_t c1, c2;
        mpz_init(c1);
        mpz_init(c2);
        elgamal.encrypt(elgamal_decimal_value,c1, c2);

        //εκτύπωση των δύο ciphertext
        printf("Encrypted Ciphertext c1 = ");
        mpz_out_str(NULL, 10, c1);
        printf("\n\n");
        printf("Encrypted Ciphertext c2 = ");
        mpz_out_str(NULL, 10, c2);
        printf("\n\n");

        //τώρα θα κάνουμε την αποκρυπτογράφηση
        mpz_t decrypted;
        mpz_init(decrypted);
        elgamal.decrypt(c1, c2, decrypted);

        //εκτύπωση, θα πρέπει να εκτυπώνεται ό,τι εκτυπώθηκε και πριν ως encoded plaintext
        printf("Decrypted (and encoded) plaintext = ");
        mpz_out_str(NULL, 10, decrypted);
        printf("\n\n");

        //η αποκρυπτογράφηση έχει τελειώσει, εδώ απλώς κάνουμε decode (από αριθμό σε string το μήνυμα)
        char* decoded;
        elgamal.decimal_to_english(decrypted, &decoded, 200);

        printf("Decoded plaintext = %s", decoded);
        delete[] decoded;

        return 0;
    }

    else if (strcmp("rabin", crypto_method) == 0) {
        CryptoRabin rabin;
        rabin.init();

        rabin.initialize_parameters();
        rabin.print_parameters();

        printf("Plaintext message = %s\n\n", input);
        mpz_t rabin_decimal_value;
        mpz_init(rabin_decimal_value);
        rabin.english_to_decimal(rabin_decimal_value, input);


        //κρυπτογράφηση
        mpz_t ciphertext;
        mpz_init(ciphertext);
        rabin.encrypt(rabin_decimal_value, ciphertext);
        printf("Encrypted Ciphertext = ");
        mpz_out_str(NULL, 10, ciphertext);
        printf("\n\n");

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
        printf("a = ");
        mpz_out_str(NULL, 10, a);
        printf("\n\n");
        printf("b = ");
        mpz_out_str(NULL, 10, b);
        printf("\n\n");
        printf("d (MUST BE 1) = ");
        mpz_out_str(NULL, 10, gcd_a_b);
        printf("\n\n");
        //αν gcd(a,b) δεν είναι 1 τότε σφάλμα
        if (mpz_cmp_ui(gcd_a_b, 1) != 0) {
            printf("Error trying to initialize the decryption process! Exiting...");
            exit(-1);
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
        printf("1)x = ");
        mpz_out_str(NULL, 10, x);
        printf("\n\n");
        printf("2)y = ");
        mpz_out_str(NULL, 10, y);
        printf("\n\n");
        printf("3)-x MOD n = ");
        mpz_out_str(NULL, 10, mx_mod_n);
        printf("\n\n");
        printf("3)-y MOD n = ");
        mpz_out_str(NULL, 10, my_mod_n);
        printf("\n\n");

        //τώρα πρέπει να βρούμε ποιό από τα 4 είναι το σωστό και τέλος να το κάνουμε decode.
        //ελέγχουμε τα 12 τελευταία στοιχεία, αν είναι '1' όλα τότε αυτό το plaintext θέλουμε και τα κόβουμε για να πάρουμε το αρχικό plaintext
        //χωρίς το redundancy
        mpz_t correct_plaintext;
        mpz_init(correct_plaintext);
        if (!rabin.get_correct_plaintext(x, y, mx_mod_n, my_mod_n, correct_plaintext))
            return -1;

        //decode το plaintext και τέλος
        char* decoded_word;
        rabin.decimal_to_english(correct_plaintext, &decoded_word, 1024);

        //εκτύπωση του plaintext
        printf("Decrypted and decoded (no redundancy) plaintext: %s", decoded_word);
        delete[] decoded_word;

        return 0;
    }

    else {
        printf("Wrong crypto method. Only 'rsa','elgamal' and 'rabin' allowed");
        return -1;
    }
}

