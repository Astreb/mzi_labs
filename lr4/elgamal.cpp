#include "elgamal.h"

mpz_class get_prime(int bits, gmp_randclass& rnd) {
	mpz_class r, max_r;
	mpz_setbit(max_r.get_mpz_t(), bits);
	
	do 
	{
		r = rnd.get_z_bits(bits - 1);
		mpz_setbit(r.get_mpz_t(), bits - 1);
		r |= 1;
		//mpz_next_prime_candidate()
		
		while (!mpz_probab_prime_p(r.get_mpz_t(), bits)) 
		{
			r += 2;
		}

	} 
	while (r >= max_r);
	
	return r;
}

mpz_class get_primitive_root(const mpz_class& p) 
{//p - is prime
	mpz_class phi = p - 1, n = phi;
	vector<mpz_class> fact;
	
	for (mpz_class i = 2; i * i <= n; ++i) 
	{
		if (n % i == 0) 
		{
			fact.push_back(i);
			
			while (n % i == 0)
				n /= i;
		}
	}

	for (size_t i = 0; i < fact.size(); ++i) 
	{
		fact[i] = phi / fact[i];
	}

	if (n > 1)
		fact.push_back(1);
	
	mpz_class rop;
	for (mpz_class res = 2; res <= p; ++res) 
	{
		bool ok = true;
		for (size_t i = 0; i < fact.size() && ok; ++i) 
		{
			mpz_powm(rop.get_mpz_t(), res.get_mpz_t(), fact[i].get_mpz_t(), p.get_mpz_t());
			ok &= rop != 1;
		}
		
		if (ok) 
			return res;
	}
	
	return -1;
}


tuple<mpz_class, mpz_class, mpz_class, mpz_class> elg_generate_key(int k) 
{
	std::random_device rd;
	gmp_randclass r(gmp_randinit_default);
	r.seed(rd());
	mpz_class p, x, g, y;
	
	p = get_prime(k, r);
	x = r.get_z_range(p - 3) + 2; //[2, p-2]
	g = get_primitive_root(p);
	mpz_powm(y.get_mpz_t(), g.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
	
	return { p, g, y, x };
}

string elg_encrypt(const string& mes, const mpz_class& p, const mpz_class& g, const mpz_class& y, int block_size) 
{
	int exp_block_size = (mpz_sizeinbase(p.get_mpz_t(), 2) + 8 - 1) / 8;
	
	if (block_size == -1) 
	{
		block_size = exp_block_size - 1;
	}
	
	int block_count = (mes.size() + block_size - 1) / block_size;
	string text(mes);
	text.resize(block_count * block_size, '\0');
	string res(2 * exp_block_size * block_count, '\0');
	mpz_t m, a, b, tmp, k, k_max, phi; // phi = p - 1
	mpz_init(m);
	mpz_init(a);
	mpz_init(b);
	mpz_init(tmp);
	mpz_init(k);
	mpz_init(k_max);
	mpz_init(phi);

	mpz_sub_ui(k_max, p.get_mpz_t(), 3);
	mpz_sub_ui(phi, p.get_mpz_t(), 1);
	random_device rd;
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, rd());

	for (int i = 0; i < block_count; i++) 
	{
		// k generate
		do 
		{
			mpz_urandomm(k, state, k_max); // k (1, p - 1)
			mpz_add_ui(k, k, 2);
			mpz_gcd(tmp, k, phi);
			
			while (mpz_cmp_ui(tmp, 1) != 0) 
			{
				mpz_nextprime(k, k);
				mpz_gcd(tmp, k, phi);
			}
		} 
		while (mpz_cmp(k, phi) > 0);
		// import
		string blk_str = text.substr(i * block_size, block_size);
		mpz_import(m, blk_str.size(), 1, sizeof(char), 0, 0, blk_str.data());

		mpz_powm(a, g.get_mpz_t(), k, p.get_mpz_t());
		mpz_powm(b, y.get_mpz_t(), k, p.get_mpz_t());
		mpz_mul(b, b, m);
		mpz_mod(b, b, p.get_mpz_t());

		int off = exp_block_size - (mpz_sizeinbase(a, 2) + 8 - 1) / 8;
		mpz_export((void*)(res.data() + 2 * i * exp_block_size + off), NULL, 1, sizeof(char), 0, 0, a);
		off = exp_block_size - (mpz_sizeinbase(b, 2) + 8 - 1) / 8;
		mpz_export((void*)(res.data() + 2 * i * exp_block_size + exp_block_size + off), NULL, 1, sizeof(char), 0, 0, b);
	}

	mpz_clears(m, a, b, tmp, k, k_max, phi, NULL);
	return res;
}

string elg_decrypt(const std::string& mes, const mpz_class& p, const mpz_class& x, int block_size) 
{
	int imp_block_size = (mpz_sizeinbase(p.get_mpz_t(), 2) + 8 - 1) / 8;
	
	if (block_size == -1) 
	{
		block_size = imp_block_size - 1;
	}
	
	int block_count = (mes.size() + 2 * imp_block_size - 1) / (2 * imp_block_size); // кол блоков (a, b)
	string text(mes);
	text.resize(2 * block_count * imp_block_size, '\0');
	string res(block_size * block_count, '\0');
	mpz_t m, a, b, tmp, xc; // phi = p - 1
	mpz_init(m);
	mpz_init(a);
	mpz_init(b);
	mpz_init(tmp);
	mpz_init(xc);
	mpz_set_ui(xc, 0);
	mpz_sub(xc, xc, x.get_mpz_t());


	for (int i = 0; i < block_count; i++) 
	{
		// import
		string blk_str = text.substr(2 * i * imp_block_size, imp_block_size);
		mpz_import(a, blk_str.size(), 1, sizeof(char), 0, 0, blk_str.data());

		blk_str = text.substr(2 * i * imp_block_size + imp_block_size, imp_block_size);
		mpz_import(b, blk_str.size(), 1, sizeof(char), 0, 0, blk_str.data());
		mpz_powm(m, a, xc, p.get_mpz_t());
		mpz_mul(m, m, b);
		mpz_mod(m, m, p.get_mpz_t());

		int off = block_size - (mpz_sizeinbase(m, 2) + 8 - 1) / 8;
		mpz_export((void*)(res.data() + i * block_size + off), NULL, 1, sizeof(char), 0, 0, m);
	}

	mpz_clears(m, a, b, tmp, xc, NULL);
	return res;
}