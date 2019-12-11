#include <mpirxx.h>
#include <iostream>
#include <tuple>
#include <string>
#include <vector>
#include <random>

using namespace std;

mpz_class get_prime(int bits, gmp_randclass& rnd);
mpz_class get_primitive_root(const mpz_class& p);

tuple<mpz_class, mpz_class, mpz_class, mpz_class> 
elg_generate_key(int k);

string elg_encrypt(const std::string& mes, const mpz_class& p, const mpz_class& g, const mpz_class& y, int block_size = -1);
string elg_decrypt(const std::string& mes, const mpz_class& p, const mpz_class& x, int block_size = -1);
