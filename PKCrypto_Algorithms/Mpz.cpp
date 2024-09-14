#include "Mpz.h"
#include <gmp.h>
#include <ostream>
#include <string>

using namespace gmp;
using std::string;

Mpz::Mpz() {
	mpz_init(_value);
}

Mpz::Mpz(const ulong n) {
	mpz_init_set_ui(_value, n);
}

Mpz::Mpz(const string str)
{
	mpz_init_set_str(_value, str.c_str(), 10);
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

bool Mpz::operator==(const Mpz& other) const
{
	return mpz_cmp(this->_value, other._value) == 0;
}

bool Mpz::operator==(ulong n) const
{
	return mpz_cmp_ui(this->_value, n) == 0;
}

bool Mpz::operator!=(const Mpz& other) const
{
	return !operator==(other);
}

bool Mpz::operator!=(ulong n) const
{
	return !operator==(n);
}

bool gmp::Mpz::operator>(const Mpz& other) const
{
	return mpz_cmp(this->_value, other._value) > 0;
}

bool Mpz::operator>(ulong n) const
{
	return mpz_cmp_ui(this->_value, n) > 0;
}

bool gmp::Mpz::operator>=(const Mpz& other) const
{
	return mpz_cmp(this->_value, other._value) >= 0;
}

bool gmp::Mpz::operator>=(ulong n) const
{
	return mpz_cmp_ui(this->_value, n) >= 0;
}

bool gmp::Mpz::operator<(const Mpz& other) const
{
	return mpz_cmp(this->_value, other._value) < 0;
}

bool gmp::Mpz::operator<(ulong n) const
{
	return mpz_cmp_ui(this->_value, n) < 0;
}

bool gmp::Mpz::operator<=(const Mpz& other) const
{
	return mpz_cmp(this->_value, other._value) <= 0;
}

bool gmp::Mpz::operator<=(ulong n) const
{
	return mpz_cmp_ui(this->_value, n) <= 0;
}

Mpz& Mpz::operator=(const Mpz& other) {
	if (this != &other) {
		mpz_set(_value, other());
	}
	return *this;
}

Mpz& Mpz::operator=(const ulong n) {
	mpz_set_ui(_value, n);
	return *this;
}

Mpz& Mpz::operator=(const string str)
{
	mpz_set_str(_value, str.c_str(), 10);
	return *this;
}

Mpz Mpz::operator-(const ulong n) const {
	Mpz mpz;
	mpz_sub_ui(mpz._value, this->_value, n);
	return mpz;
}

Mpz Mpz::operator-(const Mpz& other) const
{
	Mpz mpz;
	mpz_sub(mpz._value, this->_value, other._value);
	return mpz;
}

void gmp::Mpz::operator-=(const ulong n)
{
	mpz_sub_ui(this->_value, this->_value, n);
}

void gmp::Mpz::operator-=(const Mpz& other)
{
	mpz_sub(this->_value, this->_value, other._value);
}

Mpz gmp::Mpz::operator-() const
{
	return *this * -1UL;
}

Mpz Mpz::operator+(const ulong n) const {
	Mpz mpz;
	mpz_add_ui(mpz._value, this->_value, n);
	return mpz;
}

Mpz Mpz::operator+(const Mpz& other) const
{
	Mpz mpz;
	mpz_add(mpz._value, this->_value, other._value);
	return mpz;
}

void Mpz::operator+=(const ulong n)
{
	mpz_add_ui(this->_value, this->_value, n);
}

void Mpz::operator+=(const Mpz& other)
{
	mpz_add(this->_value, this->_value, other._value);
}

Mpz Mpz::operator*(const ulong n) const {
	Mpz mpz;
	mpz_mul_si(mpz._value, this->_value, n);
	return mpz;
}

Mpz Mpz::operator*(const Mpz& other) const
{
	Mpz mpz;
	mpz_mul(mpz._value, this->_value, other._value);
	return mpz;
}

void gmp::Mpz::operator*=(const ulong n)
{
	mpz_mul_ui(this->_value, this->_value, n);
}

void gmp::Mpz::operator*=(const Mpz& other)
{
	mpz_mul(this->_value, this->_value, other._value);
}

Mpz Mpz::operator%(const ulong n) const
{
	Mpz mpz;
	mpz_mod_ui(mpz._value, this->_value, n);
	return mpz;
}

Mpz Mpz::operator%(const Mpz& other) const
{
	Mpz mpz;
	mpz_mod(mpz._value, this->_value, other());
	return mpz;
}

void gmp::Mpz::operator%=(const ulong n)
{
	mpz_mod_ui(this->_value, this->_value, n);
}

void gmp::Mpz::operator%=(const Mpz& other)
{
	mpz_mod(this->_value, this->_value, other._value);
}

Mpz Mpz::operator/(const ulong n) const
{
	Mpz mpz;
	mpz_fdiv_q_ui(mpz._value, this->_value, n);
	return mpz;
}

Mpz Mpz::operator/(const Mpz& other) const
{
	Mpz mpz;
	mpz_fdiv_q(mpz._value, this->_value, other._value);
	return mpz;
}

void gmp::Mpz::operator/=(const ulong n)
{
	mpz_fdiv_q_ui(this->_value, this->_value, n);
}

void gmp::Mpz::operator/=(const Mpz& other)
{
	mpz_fdiv_q(this->_value, this->_value, other._value);
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

/*static methods below */

int Mpz::probab_prime_p(const Mpz& a, const int n) {
	return mpz_probab_prime_p(a._value, n);
}

Mpz Mpz::urandomb(gmp_randstate_t state, mp_bitcnt_t num) {
	Mpz mpz;
	mpz_urandomb(mpz._value, state, num);
	return mpz;
}

Mpz Mpz::powm(const Mpz& a, const Mpz& b, const Mpz& c) {
	Mpz mpz;
	mpz_powm(mpz._value, a._value, b._value, c._value);
	return mpz;
}

Mpz Mpz::powm_ui(const Mpz& a, const ulong n, const Mpz& b) {
	Mpz mpz;
	mpz_powm_ui(mpz._value, a._value, n, b._value);
	return mpz;
}
