#include "Mpz.h"
#include <gmp.h>
#include <ostream>

using gmp::Mpz;

Mpz::Mpz() {
	mpz_init(_value);
}

Mpz::Mpz(const ulong n) {
	mpz_init_set_ui(_value, n);
}

Mpz::Mpz(const Mpz &other) {
	mpz_init_set(_value, other._value);
}

Mpz::~Mpz() {
	mpz_clear(_value);
}

const mpz_t& Mpz::operator()() const { 
	return _value; 
}

Mpz::Mpz(Mpz&& other) noexcept {
	mpz_init(_value);
	mpz_swap(_value, other._value);
}

Mpz& Mpz::operator=(Mpz&& other) noexcept {
	if (this != &other) {
		mpz_swap(_value, other._value);
	}
	return *this;
}

Mpz& Mpz::operator=(const Mpz& other) {
	if (this != &other) {
		mpz_set(_value, other());
	}
	return *this;
}

std::ostream& gmp::operator<<(std::ostream& os, const Mpz& mpz)
{
	mpz_out_str(NULL, 10, mpz());
	return os;
}

bool Mpz::is_empty() const {
	return _value[0]._mp_alloc == 0;
}

std::size_t Mpz::size_in_bits() const
{
	return mpz_sizeinbase(_value, 2);
}

int Mpz::sprintf(char* a, const char* b) const {
	return gmp_sprintf(a, b, _value);
}

int Mpz::sscanf(const char* a, const char* b) const {
	return gmp_sscanf(a, b, _value);
}

int Mpz::Mpz_set_str(const char *str) {
	return mpz_set_str(_value, str, 10);
}

void Mpz::Mpz_set_ui(const ulong num) {
	mpz_set_ui(_value, num);
}

void Mpz::Mpz_pow_ui(const Mpz &a, const ulong n) {
	mpz_pow_ui(_value, a(), n);
}

int Mpz::Mpz_cmp_ui(const ulong n) const {
	return mpz_cmp_ui(_value, n);
}

int Mpz::Mpz_cmp(const Mpz& a) const {
	return mpz_cmp(_value, a());
}

void Mpz::Mpz_urandomb(gmp_randstate_t state, mp_bitcnt_t num) {
	mpz_urandomb(_value, state, num);
}

int Mpz::Mpz_probab_prime_p(const int n) const {
	return mpz_probab_prime_p(_value, n);
}

void Mpz::Mpz_mul(const Mpz &a, const Mpz &b) {
	mpz_mul(_value, a(), b());
}

void Mpz::Mpz_mul_si(const Mpz &a, const ulong n) {
	mpz_mul_si(_value, a(), n);
}

void Mpz::Mpz_sub_ui(const Mpz &a, const ulong n) {
	mpz_sub_ui(_value, a(), n);
}

void Mpz::Mpz_add_ui(const Mpz& a, const ulong n) {
	mpz_add_ui(_value, a(), n);
}

void Mpz::Mpz_fdiv_q(const Mpz &a, const Mpz &b) {
	mpz_fdiv_q(_value, a(), b());
}

void Mpz::Mpz_fdiv_q_ui(const Mpz& a, const ulong n) {
	mpz_fdiv_q_ui(_value, a(), n);
}

void Mpz::Mpz_mod(const Mpz& a, const Mpz& b) {
	mpz_mod(_value, a(), b());
}

void Mpz::Mpz_mod_ui(const Mpz& a, const ulong n) {
	mpz_mod_ui(_value, a(), n);
}

void Mpz::Mpz_sub(const Mpz& a, const Mpz& b) {
	mpz_sub(_value, a(), b());
}

void Mpz::Mpz_add(const Mpz& a, const Mpz& b) {
	mpz_add(_value, a(), b());
}

void Mpz::Mpz_powm(const Mpz& a, const Mpz& b, const Mpz& c) {
	mpz_powm(_value, a(), b(), c());
}

void Mpz::Mpz_powm_ui(const Mpz& a, const ulong n, const Mpz& b) {
	mpz_powm_ui(_value, a(), n, b());
}
