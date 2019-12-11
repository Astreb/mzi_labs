#include "des.h"

string hex_to_byte(const string& hex)
{
	int size = hex.length() / 2;
	string res;
	res.resize(size);

	for (int i = 0; i < (int)hex.length(); i += 2) 
	{
		char d = hex[i];
		d -= d <= '9' ? '0' : 'A' - 10;
		char d2 = hex[i + 1];
		d2 -= d2 <= '9' ? '0' : 'A' - 10;
		d = (d << 4) | d2;
		res[i / 2] = d;
	}

	return res;
}

string hex_to_string(const string& hex)
{
	int size = hex.length() / 2;
	string res;
	res.resize(size);

	for (int i = 0; i < (int)hex.length(); i += 2) 
	{
		char d = hex[i];
		d -= d <= '9' ? '0' : 'A' - 10;
		char d2 = hex[i + 1];
		d2 -= d2 <= '9' ? '0' : 'A' - 10;
		d = (d << 4) | d2;
		res[i / 2] = d;
	}

	return res;
}

DES::DES(const bitset<56> &key)
{
	keygen(expand(key));
}

DES::DES(const bitset<64> & key)
{
	keygen(key);
}

DES::DES(const string & stringkey) 
{
	int byte_count = stringkey.length();
	if (byte_count == 8)
		keygen(string_to_set<64>(stringkey));
	else 
		keygen(expand(string_to_set<56>(stringkey)));
}

string DES::encrypt(const string& text)
{
	string text_ex = text;
	int blocks_count = (text_ex.length() + 7) / 8;
	text_ex.resize(blocks_count * 8);
	string res(blocks_count * 8, '\0');

	for (int b = 0; b < blocks_count; b++)
	{
		bitset<64> block;
		for (int i = 0; i < 8; i++)
			for (int j = 0; j < 8; j++)
				block[i * 8 + j] = text_ex[b * 8 + i] & (1 << (7 - j));
		bitset<64> coded_block = encrypt_block(block);
		for (int i = 0; i < 8; i++)
			for (int j = 0; j < 8; j++)
				res[b * 8 + i] |= ((coded_block[i * 8 + j] ? 1 : 0) << (7 - j));
	}

	return res;
}

string DES::decrypt(const string& text)
{
	string text_ex = text;
	int blocks_count = (text_ex.length() + 7) / 8;
	text_ex.resize(blocks_count * 8);
	string res(blocks_count * 8, '\0');

	for (int b = 0; b < blocks_count; b++)
	{
		bitset<64> block;
		for (int i = 0; i < 8; i++)
			for (int j = 0; j < 8; j++)
				block[i * 8 + j] = text_ex[b * 8 + i] & (1 << (7 - j));
		bitset<64> decoded_block = decrypt_block(block);
		for (int i = 0; i < 8; i++)
			for (int j = 0; j < 8; j++)
				res[b * 8 + i] |= ((decoded_block[i * 8 + j] ? 1 : 0) << (7 - j));
	}

	return res;
}

bitset<64> DES::encrypt_block(const bitset<64> & block)
{
	return des(block, true);
}

bitset<64> DES::decrypt_block(const bitset<64> & block)
{
	return des(block, false);
}

bitset<64> DES::des(const bitset<64> & block, bool mode) 
{
	bitset<64> res;
	res = permutate(block, IP);
	bitset<32> left;
	bitset<32> right;
	bitset<32> f;
	bool bit;

	for (int i = 0; i < 32; i++)
	{
		left[i] = res[i];
		right[i] = res[32 + i];
	}

	for (int i = 0; i < 16; i++)
	{
		if (mode) f = fejstel_func(right, subkeys[i]);
		else f = fejstel_func(right, subkeys[15 - i]);
		for (int i = 0; i < 32; i++)
		{
			bit = left[i];
			left[i] = right[i];
			right[i] = bit ^ f[i];
		}
	}

	for (int i = 0; i < 32; i++)
	{
		res[i] = right[i];
		res[32 + i] = left[i];
	}

	res = permutate(res, IP_1);
	return res;
}

bitset<32> DES::fejstel_func(const bitset<32> & r, const bitset<48> & key)
{
	bitset<48> er;
	er = permutate(r, E);
	bitset<48> B;

	for (int i = 0; i < 48; i++)
		B[i] = er[i] ^ key[i];

	array<bitset<6>, 8> b;

	for (int i = 0; i < 48; i++)
		b[i / 6][i % 6] = B[i];

	array<bitset<4>, 8> b_;

	for (int i = 0; i < 8; i++)
	{
		int row = ((b[i][0] ? 1 : 0) << 1) + (b[i][5] ? 1 : 0);
		int col =
			((b[i][1] ? 1 : 0) << 3) +
			((b[i][2] ? 1 : 0) << 2) +
			((b[i][3] ? 1 : 0) << 1) +
			((b[i][4] ? 1 : 0) << 0);
		for (int j = 0; j < 4; j++)
			b_[i][j] = S[i][row][col][3 - j];
	}

	bitset<32> B_;

	for (int i = 0; i < 8; i++)
		for (int j = 0; j < 4; j++)
			B_[i * 4 + j] = b_[i][j];

	bitset<32> res;
	res = permutate(B_, P);
	return res;
}

bitset<28> left_shift(const bitset<28> & set, int size)
{
	bitset<28> res;

	for (int i = 0; i < 28; i++)
	{
		res[i] = set[(i + size + 28) % 28];
	}

	return res;
}

void DES::keygen(const bitset<64> & exkey) 
{
	bitset<28> c = permutate(exkey, C);
	bitset<28> d = permutate(exkey, D);
	bitset<56> cd;

	for (int i = 0; i < 16; i++) 
	{
		c = left_shift(c, CD_shift[i]);
		d = left_shift(d, CD_shift[i]);

		for (int i = 0; i < 28; i++)
		{
			cd[i] = c[i];
			cd[i + 28] = d[i];
		}

		subkeys[i] = permutate(cd, CD_select);
	}
}

bitset<64> DES::expand(const bitset<56> & key)
{
	bitset<64> res;
	int i = 0;

	for (int j = 0; j < 8; j++)
	{
		bool even = true;
		for (int k = 0; k < 7; k++)
		{
			res[i++] = key[j * 7 + k];
			if (res[i] == true) even = !even;
		}
		if (even) res[i++] = true;
		else res[i++] = false;
	}

	return res;
}