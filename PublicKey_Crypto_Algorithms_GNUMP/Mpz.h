#pragma once
#include <gmp.h>

namespace gmp {
	class Mpz
	{
	private:
		mpz_t _value;
	public:
		Mpz();
		Mpz(unsigned long int);
		Mpz(const Mpz& a);
		Mpz(const Mpz&& a) = delete;
		~Mpz();

		auto inline get() const { return _value; ; }
		auto inline operator()() const { return get(); }
		Mpz& operator=(const Mpz& t) { mpz_set(_value, t()); return *this; }

		int sprintf(char*, const char*) const;
		int sscanf(const char*, const char*);

		void Mpz_urandomb(gmp_randstate_t, mp_bitcnt_t);
		int Mpz_probab_prime_p(int num);

		void Mpz_set_ui(unsigned long int num);
		int Mpz_cmp(const Mpz& a);
		int Mpz_cmp_ui(unsigned long int num);
		void Mpz_pow_ui(const Mpz& a, unsigned long int num);
		int Mpz_set_str(const char*);
		void Mpz_out_str();

		void Mpz_mul(const Mpz& a, const Mpz& b);
		void Mpz_mul_si(const Mpz& a, unsigned long int n);
		void Mpz_add(const Mpz& a, const Mpz& b);
		void Mpz_add_ui(const Mpz& a, unsigned long int n);
		void Mpz_sub(const Mpz& a, const Mpz& b);
		void Mpz_sub_ui(const Mpz& a, unsigned long int n);
		void Mpz_fdiv_q(const Mpz& a, const Mpz& b);
		void Mpz_fdiv_q_ui(const Mpz& a, unsigned long int n);
		void Mpz_mod(const Mpz& a, const Mpz& b);
		void Mpz_mod_ui(const Mpz& a, unsigned long int n);
		void Mpz_powm(const Mpz& a, const Mpz& b, const Mpz& c);
		void Mpz_powm_ui(const Mpz& a, unsigned long int, const Mpz& b);
	};
}

