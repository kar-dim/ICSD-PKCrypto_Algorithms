#pragma once
#include <gmp.h>

using ulong = unsigned long int;

namespace gmp {
	class Mpz
	{
	private:
		mpz_t _value;
	public:
		Mpz();
		Mpz(const ulong);
		Mpz(const Mpz& other);
		~Mpz();

		auto inline get() const { return _value; }
		auto inline operator()() const { return get(); }
		Mpz& operator=(const Mpz& t) { mpz_set(_value, t()); return *this; }

		bool isEmpty() const;

		int sprintf(char*, const char*) const;
		int sscanf(const char*, const char*) const;

		void Mpz_urandomb(gmp_randstate_t, mp_bitcnt_t);
		int Mpz_probab_prime_p(const int num) const;

		void Mpz_set_ui(const ulong num);
		int Mpz_cmp(const Mpz& a) const;
		int Mpz_cmp_ui(const ulong num) const;
		void Mpz_pow_ui(const Mpz& a, const ulong num);
		int Mpz_set_str(const char*);
		void Mpz_out_str() const;

		void Mpz_mul(const Mpz& a, const Mpz& b);
		void Mpz_mul_si(const Mpz& a, const ulong n);
		void Mpz_add(const Mpz& a, const Mpz& b);
		void Mpz_add_ui(const Mpz& a, const ulong n);
		void Mpz_sub(const Mpz& a, const Mpz& b);
		void Mpz_sub_ui(const Mpz& a, const ulong n);
		void Mpz_fdiv_q(const Mpz& a, const Mpz& b);
		void Mpz_fdiv_q_ui(const Mpz& a, const ulong n);
		void Mpz_mod(const Mpz& a, const Mpz& b);
		void Mpz_mod_ui(const Mpz& a, const ulong n);
		void Mpz_powm(const Mpz& a, const Mpz& b, const Mpz& c);
		void Mpz_powm_ui(const Mpz& a, const ulong n, const Mpz& b);
	};
}

