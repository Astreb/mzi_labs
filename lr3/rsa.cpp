#include "rsa.h"

tuple<mpz_class, mpz_class, mpz_class> rsa_generate_key(unsigned int keysize) {
	random_device rd;
	mpz_t p, q, ec, phi, tmp, tmp2;
	mpz_init(p);
	mpz_init(q);
	mpz_init(ec);
	mpz_init(phi);
	mpz_init(tmp);
	mpz_init(tmp2);

	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, rd());

	mpz_urandomb(tmp, state, keysize / 2);
	mpz_setbit(tmp, keysize / 2 - 1);
	mpz_nextprime(p, tmp);

	int bits = keysize - mpz_sizeinbase(p, 2);
	mpz_t max_q, key;
	mpz_init(max_q);
	mpz_init(key);
	mpz_setbit(key, keysize);
	mpz_div(max_q, key, p);
	
	do 
	{
		mpz_urandomb(q, state, bits + 1);
		mpz_setbit(q, bits);
		mpz_nextprime(q, q);
	} 
	while (mpz_cmp(p, q) == 0 || mpz_cmp(q, max_q) > 0);
	mpz_sub_ui(tmp, p, 1);
	mpz_sub_ui(tmp2, q, 1);
	mpz_mul(phi, tmp, tmp2);
	mpz_div_ui(tmp, phi, 2);
	//generate e
	//
	do 
	{
		mpz_urandomm(ec, state, tmp); //tmp = phi/2
		do
		{
			mpz_nextprime(ec, ec);
			//mpz_add_ui(ec, ec, 1);
			mpz_gcd(tmp2, ec, phi);
		} 
		while (mpz_cmp_ui(tmp2, 1) != 0);
	} 
	while (mpz_cmp(ec, phi) >= 0);


	mpz_mul(tmp, p, q);
	mpz_invert(tmp2, ec, phi);
	mpz_class e(ec), d(tmp2), n(tmp);
	mpz_clears(p, q, ec, phi, tmp, tmp2, max_q, key, NULL);
	return { e, d, n };
}

string rsa_encrypt(string& message, const mpz_class& e, const mpz_class& n, int block_size) 
{
	int export_block_size = (mpz_sizeinbase(n.get_mpz_t(), 2) + 8 - 1) / 8;
	if (block_size == -1) block_size = export_block_size - 1;
	int block_count = (message.length() + block_size - 1) / block_size;
	string text(message);
	text.resize(block_count * block_size, '\0');

	string res(block_count * export_block_size, '\0');
	string tmp_str(block_size, '\0');
	mpz_t m, r;
	mpz_init(m);
	mpz_init(r);

	for (int i = 0; i < block_count; i++) 
	{
		for (int j = 0; j < block_size; j++) 
		{
			tmp_str[j] = text[i * block_size + j];
		}
		
		mpz_import(m, block_size, 1, sizeof(char), 0, 0, tmp_str.data());
		mpz_powm(r, m, e.get_mpz_t(), n.get_mpz_t());
		int off = export_block_size - (mpz_sizeinbase(r, 2) + 8 - 1) / 8;
		mpz_export((void*)(res.data() + i * export_block_size + off), NULL, 1, sizeof(char), 0, 0, r);
	}

	mpz_clears(m, r, NULL);
	return res;
}

string rsa_decrypt(const string& message, const mpz_class& d, const mpz_class& n, int block_size) 
{
	int import_b_size = (mpz_sizeinbase(n.get_mpz_t(), 2) + 8 - 1) / 8;
	if (block_size == -1) block_size = import_b_size - 1;
	int block_count = (message.length() + import_b_size - 1) / import_b_size;
	string text(message);
	text.resize(block_count * import_b_size, '\0');

	string res(block_count * block_size, '\0');
	string tmp_str(import_b_size, '\0');
	mpz_t m, r;
	mpz_init(m);
	mpz_init(r);

	for (int i = 0; i < block_count; i++) 
	{
		for (int j = 0; j < import_b_size; j++) 
		{
			tmp_str[j] = text[i * import_b_size + j];
		}
		
		mpz_import(m, import_b_size, 1, sizeof(char), 0, 0, tmp_str.data());
		mpz_powm(r, m, d.get_mpz_t(), n.get_mpz_t());
		int off = block_size - (mpz_sizeinbase(r, 2) + 8 - 1) / 8;
		mpz_export((void*)(res.data() + i * block_size + off), NULL, 1, sizeof(char), 0, 0, r);
	}

	mpz_clears(m, r, NULL);
	return res;
}


tuple<mpz_class, mpz_class, mpz_class> rsa_generate_key2(unsigned int keysize, const mpz_class& e) 
{
	random_device rd;
	mpz_t tmp; mpz_init(tmp);

	mpz_class p, q, phi, d, n;
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, rd());

	mpz_urandomb(tmp, state, keysize / 2);
	mpz_setbit(tmp, keysize / 2 - 1);
	mpz_nextprime(p.get_mpz_t(), tmp);
	
	while (p % e == 1) 
	{
		mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
	}
	
	int bits = keysize - mpz_sizeinbase(p.get_mpz_t(), 2);
	mpz_class max_q, key;
	mpz_setbit(key.get_mpz_t(), keysize);
	max_q = (key - 1) / p;
	
	do 
	{
		mpz_urandomb(tmp, state, bits + 1);
		mpz_setbit(tmp, bits);

		mpz_nextprime(q.get_mpz_t(), tmp);
		while (q % e == 1) 
		{
			mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
		}
	} 
	while (p == q || q > max_q);
	
	n = p * q;
	phi = (p - 1) * (q - 1);
	mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
	mpz_gcd(key.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
	mpz_clear(tmp);
	
	return { e, d, n };
}