#include "mpirxx.h"
#include <tuple>
#include <random>
#include <vector>
#include <iostream>

using namespace std;

tuple<mpz_class, mpz_class, mpz_class>
rsa_generate_key(unsigned int keysize);

tuple<mpz_class, mpz_class, mpz_class>
rsa_generate_key2(unsigned int keysize, const mpz_class& e=17);

string rsa_encrypt(const string& message, const mpz_class& e, const mpz_class& n, int block_size=-1);
string rsa_decrypt(const string& message, const mpz_class& d, const mpz_class& n, int block_size=-1);
