#pragma once
#include <gmp.h>
#include <ostream>
#include <string>

using ulong = unsigned long int;

namespace gmp {
	class Mpz
	{
	private:
		mpz_t _value;
	public:
		Mpz();
		~Mpz();
		explicit Mpz(const ulong);
		explicit Mpz(const std::string& str);
		Mpz(const Mpz& other);
		Mpz(Mpz&& other) noexcept;

		//operators
		const mpz_t& operator()() const;
		Mpz& operator=(const ulong n);
		Mpz& operator=(const std::string& str);
		Mpz& operator=(const Mpz& other);
		Mpz& operator=(Mpz&& other) noexcept;
		bool operator==(const Mpz& other) const;
		bool operator==(ulong n) const;
		bool operator!=(const Mpz& other) const;
		bool operator!=(ulong n) const;
		bool operator>(const Mpz& other) const;
		bool operator>(ulong n) const;
		bool operator>=(const Mpz& other) const;
		bool operator>=(ulong n) const;
		bool operator<(const Mpz& other) const;
		bool operator<(ulong n) const;
		bool operator<=(const Mpz& other) const;
		bool operator<=(ulong n) const;
		Mpz operator-(const ulong n) const;
		Mpz operator-(const Mpz& other) const;
		void operator-=(const ulong n);
		void operator-=(const Mpz& other);
		Mpz operator-() const;
		Mpz operator+(const ulong n) const;
		Mpz operator+(const Mpz& other) const;
		void operator+=(const ulong n);
		void operator+=(const Mpz& other);
		Mpz operator*(const ulong n) const;
		Mpz operator*(const Mpz& other) const;
		void operator*=(const ulong n);
		void operator*=(const Mpz& other);
		Mpz operator%(const ulong n) const;
		Mpz operator%(const Mpz& other) const;
		void operator%=(const ulong n);
		void operator%=(const Mpz& other);
		Mpz operator/(const ulong n) const;
		Mpz operator/(const Mpz& other) const;
		void operator/=(const ulong n);
		void operator/=(const Mpz& other);
		char* get_str(char* str, int base) const;
		friend std::ostream& operator<<(std::ostream& os, const Mpz& mpz);

		//helper methods
		bool is_empty() const;
		size_t size_in_bits() const;
		int sprintf(char*, const char*) const;
		int sscanf(const char*, const char*) const;

		//static methods
		static gmp::Mpz powm(const Mpz& a, const Mpz& b, const Mpz& c);
		static gmp::Mpz powm_ui(const Mpz& a, const ulong n, const Mpz& b);
		static gmp::Mpz pow_ui(const ulong base, const ulong exp);
		static unsigned int get_ui(const Mpz& a);
		static gmp::Mpz urandomb(gmp_randstate_t, mp_bitcnt_t);
		static int probab_prime_p(const Mpz& a, const int num);
	};
}

