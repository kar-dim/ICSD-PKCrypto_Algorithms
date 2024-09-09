#include "Mpz.h"
#include <gmp.h>

gmp::Mpz::Mpz() {
	mpz_init(_value);
}

gmp::Mpz::Mpz(const ulong n) {
	mpz_init_set_ui(_value, n);
}

gmp::Mpz::Mpz(const gmp::Mpz &other) {
	mpz_init_set(_value, other._value);
}

gmp::Mpz::~Mpz() {
	mpz_clear(_value);
}

bool gmp::Mpz::isEmpty() const {
	return _value[0]._mp_alloc == 0;
}

int gmp::Mpz::sprintf(char* a, const char* b) const {
	return gmp_sprintf(a, b, _value);
}

int gmp::Mpz::sscanf(const char* a, const char* b) const {
	return gmp_sscanf(a, b, _value);
}

int gmp::Mpz::Mpz_set_str(const char *str) {
	return mpz_set_str(_value, str, 10);
}

void gmp::Mpz::Mpz_out_str() const {
	mpz_out_str(NULL, 10, _value);
}

void gmp::Mpz::Mpz_set_ui(const ulong num) {
	mpz_set_ui(_value, num);
}

void gmp::Mpz::Mpz_pow_ui(const gmp::Mpz &a, const ulong n) {
	mpz_pow_ui(_value, a(), n);
}

int gmp::Mpz::Mpz_cmp_ui(const ulong n) const {
	return mpz_cmp_ui(_value, n);
}

int gmp::Mpz::Mpz_cmp(const gmp::Mpz& a) const {
	return mpz_cmp(_value, a());
}

void gmp::Mpz::Mpz_urandomb(gmp_randstate_t state, mp_bitcnt_t num) {
	mpz_urandomb(_value, state, num);
}

int gmp::Mpz::Mpz_probab_prime_p(const int n) const {
	return mpz_probab_prime_p(_value, n);
}

void gmp::Mpz::Mpz_mul(const gmp::Mpz &a, const gmp::Mpz &b) {
	mpz_mul(_value, a(), b());
}

void gmp::Mpz::Mpz_mul_si(const gmp::Mpz &a, const ulong n) {
	mpz_mul_si(_value, a(), n);
}

void gmp::Mpz::Mpz_sub_ui(const gmp::Mpz &a, const ulong n) {
	mpz_sub_ui(_value, a(), n);
}

void gmp::Mpz::Mpz_add_ui(const gmp::Mpz& a, const ulong n) {
	mpz_add_ui(_value, a(), n);
}

void gmp::Mpz::Mpz_fdiv_q(const gmp::Mpz &a, const gmp::Mpz &b) {
	mpz_fdiv_q(_value, a(), b());
}

void gmp::Mpz::Mpz_fdiv_q_ui(const gmp::Mpz& a, const ulong n) {
	mpz_fdiv_q_ui(_value, a(), n);
}

void gmp::Mpz::Mpz_mod(const gmp::Mpz& a, const gmp::Mpz& b) {
	mpz_mod(_value, a(), b());
}

void gmp::Mpz::Mpz_mod_ui(const gmp::Mpz& a, const ulong n) {
	mpz_mod_ui(_value, a(), n);
}

void gmp::Mpz::Mpz_sub(const gmp::Mpz& a, const gmp::Mpz& b) {
	mpz_sub(_value, a(), b());
}

void gmp::Mpz::Mpz_add(const gmp::Mpz& a, const gmp::Mpz& b) {
	mpz_add(_value, a(), b());
}

void gmp::Mpz::Mpz_powm(const gmp::Mpz& a, const gmp::Mpz& b, const gmp::Mpz& c) {
	mpz_powm(_value, a(), b(), c());
}

void gmp::Mpz::Mpz_powm_ui(const gmp::Mpz& a, const ulong n, const gmp::Mpz& b) {
	mpz_powm_ui(_value, a(), n, b());
}

