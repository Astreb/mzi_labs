#include <string>
#include <iostream>
#include <bitset>
#include <array>
#include <istream>
#include <fstream>

using namespace std;

const array<bitset<8>, 256> H{
	0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
	0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
	0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B,
	0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99,
	0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1,
	0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F,
	0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31,
	0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93,
	0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
	0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
	0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2,
	0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11,
	0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1,
	0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A,
	0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21,
	0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D, };

template<int size> void print_hex(const bitset<size>& set, const string& end = "\n")
{
	for (int i = 0; i < size / 8; i++)
	{
		char d =
			((set[i * 8 + 4] ? 1 : 0) << 0) |
			((set[i * 8 + 5] ? 1 : 0) << 1) |
			((set[i * 8 + 6] ? 1 : 0) << 2) |
			((set[i * 8 + 7] ? 1 : 0) << 3);
		d += d < 10 ? '0' : 'A' - 10;
		cout << d;
		d =
			((set[i * 8 + 0] ? 1 : 0) << 0) |
			((set[i * 8 + 1] ? 1 : 0) << 1) |
			((set[i * 8 + 2] ? 1 : 0) << 2) |
			((set[i * 8 + 3] ? 1 : 0) << 3);
		d += d < 10 ? '0' : 'A' - 10;
		cout << d;
	}
	cout << end;
}

// size%4 = 0
template<int size> bitset<size> hex_to_set(const string& hex)
{
	bitset<size> res;
	string text(hex);
	int byte = (hex.size() + 1) / 2;
	text.resize(byte * 2, '\0');

	for (int i = 0; i < byte * 2; i += 2) 
	{
		swap(text[i], text[i + 1]);
	}

	for (int i = 0; i < byte * 2 && i < size / 4; i++) 
	{
		char d = text[i];
		d -= d <= '9' ? '0' : 'A' - 10;
		for (int j = 0; j < 4; j++)
			res[i * 4 + j] = (d & (1 << j));
	}

	return res;
}

template<int size> string set_to_hex_string(const bitset<size> set) 
{
	string res(size / 4, '\0');
	for (int i = 0; i < size / 4; i++) 
	{
		char d =
			((set[i * 4 + 0] ? 1 : 0) << 0) |
			((set[i * 4 + 1] ? 1 : 0) << 1) |
			((set[i * 4 + 2] ? 1 : 0) << 2) |
			((set[i * 4 + 3] ? 1 : 0) << 3);
		d += d < 10 ? '0' : 'A' - 10;
		res[i] = d;
	}

	for (int i = 0; i < size / 4; i += 2) 
	{
		swap(res[i], res[i + 1]);
	}

	return res;
}


template<int size> string set_to_string(const bitset<size> bs, int res_bytes = -1) 
{
	int cnt = res_bytes == -1 ? size / 8 : res_bytes;
	string res(cnt, '\0');
	for (int i = 0; i < cnt; i++) 
	{
		for (int j = 0; j < 8; j++) 
		{
			res[i] |= ((bs[i * 8 + j] ? 1 : 0) << j);
		}
	}

	return res;
}

template<int size> static bitset<size> string_to_set(const string& str)
{
	bitset<size> res;
	int byte_count = size / 8;
	if (str.size() < byte_count)
		byte_count = str.size();

	for (int i = 0; i < byte_count; i++)
	{
		for (int j = 0; j < 8; j++)
			res[i * 8 + j] = str[i] & (1 << j);
	}

	return res;
}

template<int size> bitset<size> rotl(const bitset<size>& bs, int n) 
{
	return (bs << n) | (bs >> (size - n));
}

bitset<32> G(bitset<32> u, int r) 
{
	bitset<8> byte;
	bitset<32> sum;

	for (int i = 0; i < 4; i++) 
	{
		for (int j = 0; j < 8; j++)
			byte[j] = u[i * 8 + j];

		byte = H[byte.to_ulong()];
		for (int j = 0; j < 8; j++)
			sum[i * 8 + j] = byte[j];
	}

	return rotl(sum, r);
}


bitset<128> F(const bitset<128>& x, const bitset<256>& tetta) 
{
	array<bitset<32>, 8> keys;
	bitset<128> y;

	for (int i = 0; i < 8; i++) 
	{
		for (int j = 0; j < 32; j++) 
		{
			keys[i][j] = tetta[i * 32 + j];
		}
	}

	bitset<32> a, b, c, d, e;
	for (int i = 0; i < 32; i++) 
	{
		a[i] = x[i];
		b[i] = x[32 + i];
		c[i] = x[64 + i];
		d[i] = x[96 + i];
	}

	for (int i = 1; i <= 8; i++) 
	{
		b ^= G(a.to_ulong() + keys[(7 * i - 7) % 8].to_ulong(), 5);
		c ^= G(d.to_ulong() + keys[(7 * i - 6) % 8].to_ulong(), 21);
		a = a.to_ulong() - (G(b.to_ulong() + keys[(7 * i - 5) % 8].to_ulong(), 13).to_ulong());
		e = G(b.to_ulong() + c.to_ulong() + keys[(7 * i - 4) % 8].to_ulong(), 21) ^ bitset<32>(i);
		b = b.to_ulong() + e.to_ulong();
		c = c.to_ulong() - e.to_ulong();
		d = d.to_ulong() + G(c.to_ulong() + keys[(7 * i - 3) % 8].to_ulong(), 13).to_ulong();
		b ^= G(a.to_ulong() + keys[(7 * i - 2) % 8].to_ulong(), 21);
		c ^= G(d.to_ulong() + keys[(7 * i - 1) % 8].to_ulong(), 5);
		swap(a, b);
		swap(c, d);
		swap(b, c);
	}

	for (int i = 0; i < 32; i++) 
	{
		y[i] = b[i];
		y[32 + i] = d[i];
		y[64 + i] = a[i];
		y[96 + i] = c[i];
	}

	return y;
}

bitset<128> F_1(const bitset<128>& x, const bitset<256>& tetta) 
{
	array<bitset<32>, 8> keys;
	for (int i = 0; i < 8; i++) 
	{
		for (int j = 0; j < 32; j++) 
		{
			keys[i][j] = tetta[i * 32 + j];
		}
	}

	bitset<32> a, b, c, d, e;
	for (int i = 0; i < 32; i++) 
	{
		a[i] = x[i];
		b[i] = x[32 + i];
		c[i] = x[64 + i];
		d[i] = x[96 + i];
	}

	for (int i = 8; i >= 1; i--) 
	{
		b ^= G(a.to_ulong() + keys[(7 * i - 1) % 8].to_ulong(), 5);
		c ^= G(d.to_ulong() + keys[(7 * i - 2) % 8].to_ulong(), 21);
		a = a.to_ulong() - G(b.to_ulong() + keys[(7 * i - 3) % 8].to_ulong(), 13).to_ulong();
		e = G(b.to_ulong() + c.to_ulong() + keys[(7 * i - 4) % 8].to_ulong(), 21) ^ bitset<32>(i);
		b = b.to_ulong() + e.to_ulong();
		c = c.to_ulong() - e.to_ulong();
		d = d.to_ulong() + G(c.to_ulong() + keys[(7 * i - 5) % 8].to_ulong(), 13).to_ulong();
		b ^= G(a.to_ulong() + keys[(7 * i - 6) % 8].to_ulong(), 21);
		c ^= G(d.to_ulong() + keys[(7 * i - 7) % 8].to_ulong(), 5);
		swap(a, b);
		swap(c, d);
		swap(a, d);
	}

	bitset<128> y;
	for (int i = 0; i < 32; i++) 
	{
		y[i] = c[i];
		y[32 + i] = a[i];
		y[64 + i] = d[i];
		y[96 + i] = b[i];
	}

	return y;
}

string simple_replace(
	const string& text,
	const bitset<256>& key,
	bitset<128> (*fun)(const bitset<128>&, const bitset<256>&)) 
{
	int n = (text.size() + 15) / 16;
	string res;
	int n_shift = 0;
	int m = text.size() % 16;
	if (m) n_shift = -2;
	bitset<128> y;

	for (int i = 0; i < n + n_shift; i++) 
	{
		y = fun(string_to_set<128>(text.substr(i*16, 16)), key);
		res += set_to_string(y);
	}

	if (n_shift == -2) 
	{
		bitset<128> r, x_n;
		r = fun(string_to_set<128>(text.substr((n - 2) * 16, 16)), key);
		x_n = string_to_set<128>(text.substr((n - 1) * 16)); // возмет до конца строки, преобразует в bitset<128>, старгшие биты в нуль 
		for (int i = m * 8; i < 128; i++)
			x_n[i] = r[i];
		x_n = fun(x_n, key);
		res += set_to_string(x_n);
		res += set_to_string(r, m);
	}

	return res;
}

// text.size() >= 16 - обязательное условие(в самом стандарте)
string concanate_block_encrypt(
	const string& text,
	bitset<256>& key, bitset<128>& s,
	bitset<128>(*fun)(const bitset<128>&, const bitset<256>&)) 
{
	int n = (text.size() + 15) / 16;
	string res;
	int n_shift = 0;
	int m = text.size() % 16;
	if (m) n_shift = -2;
	bitset<128> y = s;

	for (int i = 0; i < n + n_shift; i++) 
	{
		y = fun(string_to_set<128>(text.substr(i * 16, 16)) ^ y , key);
		res += set_to_string(y);
	}

	if (n_shift == -2) 
	{
		bitset<128> r, x_n;
		r = fun(string_to_set<128>(text.substr((n - 2) * 16, 16)) ^ y, key);
		x_n = string_to_set<128>(text.substr((n - 1) * 16)); 
		x_n = fun(x_n ^ r, key);
		res += set_to_string(x_n);
		res += set_to_string(r, m);
	}

	return res;
}

string concanate_block_decrypt(
	const string& text,
	bitset<256> & key, bitset<128> & s,
	bitset<128>(*fun)(const bitset<128>&, const bitset<256>&))
{

	int n = (text.size() + 15) / 16;
	string res;
	int n_shift = 0;
	int m = text.size() % 16;
	if (m) n_shift = -2;
	bitset<128> y;
	bitset<128> x = s, x1;

	for (int i = 0; i < n + n_shift; i++) 
	{
		x1 = string_to_set<128>(text.substr(i * 16, 16));
		y = fun(x1, key) ^ x;
		res += set_to_string(y);
		x = x1;
	}

	if (n_shift == -2) 
	{
		bitset<128> r, x_n;
		x1 = string_to_set<128>(text.substr((n - 2) * 16, 16));
		x_n = string_to_set<128>(text.substr((n - 1) * 16));
		r = fun(x1 , key) ^ x_n;
		for (int i = m * 8; i < 128; i++)
			x_n[i] = r[i];
		x_n = fun(x_n, key) ^ x1;
		res += set_to_string(x_n);
		res += set_to_string(r, m);
	}

	return res;
}

string gamming_encrypt(
	const string& text,
	bitset<256> & key, bitset<128> & s,
	bitset<128>(*fun)(const bitset<128>&, const bitset<256>&))
{
	int n = (text.size() + 15) / 16;
	string res;
	int n_shift = 0, m = text.size() % 16;
	if (m) n_shift = -1;
	bitset<128> y = s, x;

	for (int i = 0; i < n + n_shift; i++) 
	{
		x = string_to_set<128>(text.substr(i * 16, 16));
		y = x ^ fun(y, key);
		res += set_to_string(y);
	}

	if (n_shift == -1) 
	{
		x = string_to_set<128>(text.substr((n - 1) * 16)); 
		y = x ^ fun(y, key);
		res += set_to_string(y, m);
	}

	return res;
}

string gamming_decrypt(
	const string& text,
	bitset<256> & key, bitset<128> & s,
	bitset<128>(*fun)(const bitset<128>&, const bitset<256>&))
{
	int n = (text.size() + 15) / 16;
	string res;
	int n_shift = 0, m = text.size() % 16;
	if (m) n_shift = -1;
	bitset<128> y, x = s, x1;

	for (int i = 0; i < n + n_shift; i++) 
	{
		x1 = string_to_set<128>(text.substr(i * 16, 16));
		y = x1 ^ fun(x, key);
		res += set_to_string(y);
		x = x1;
	}

	if (n_shift == -1) 
	{
		x1 = string_to_set<128>(text.substr((n - 1) * 16));
		y = x1 ^ fun(x, key);
		res += set_to_string(y, m);
	}

	return res;
}

template<int size> bitset<size> bitset_inc(const bitset<size>& bs) 
{
	bitset<size> res(bs);
	for (int i = 0; i < size; i++) 
	{
		if (!res[i]) 
		{
			res[i] = 1;
			break;
		}
		res[i] = 0;
	}

	return res;
}

string counter(
	const string& text,
	bitset<256> & key, bitset<128> & s,
	bitset<128>(*fun)(const bitset<128>&, const bitset<256>&))
{
	int n = (text.size() + 15) / 16;
	string res;
	int n_shift = 0, m = text.size() % 16;
	if (m) n_shift = -1;
	bitset<128> y, ss = fun(s, key), x;

	for (int i = 0; i < n + n_shift; i++) 
	{
		ss = bitset_inc(ss);
		x = string_to_set<128>(text.substr(i * 16, 16));
		y = x ^ fun(ss, key);
		res += set_to_string(y);
	}

	if (n_shift == -1) 
	{
		ss = bitset_inc(ss);
		x = string_to_set<128>(text.substr((n - 1) * 16));
		y = x ^ fun(ss, key);
		res += set_to_string(y, m);
	}

	return res;
}


void test_simple_raplace_test1() 
{
	bitset<384> x = hex_to_set<384>("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B");
	bitset<256> t = hex_to_set<256>("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
	string s_x = set_to_string(x);
	string res = simple_replace(s_x, t, F);
	cout << set_to_hex_string(string_to_set<384>(res)) << endl;
}

void test_simple_raplace_test2() 
{
	bitset<376> x = hex_to_set<376>("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B89");
	bitset<256> t = hex_to_set<256>("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
	string s_x = set_to_string(x);
	string res = simple_replace(s_x, t, F);
	cout << set_to_hex_string(string_to_set<376>(res)) << endl;

}

void test_simple_raplace_test3() 
{
	bitset<384> x = hex_to_set<384>("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B637C306ADD4EA7799EB23D31");
	bitset<256> t = hex_to_set<256>("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
	string s_x = set_to_string(x);
	string res = simple_replace(s_x, t, F_1);
	string hex_res = set_to_hex_string(string_to_set<384>(res));
	cout << hex_res << endl;
}

void test_simple_raplace_test4() 
{
	bitset<288> x = hex_to_set<288>("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B");
	bitset<256> t = hex_to_set<256>("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
	string s_x = set_to_string(x);
	string res = simple_replace(s_x, t, F_1);
	string true_res = "69CCA1C93557C9E3D66BC3E0FA88FA6E5F23102EF109710775017F73806DA9DC46FB2ED2CE771F26DCB5E5D1569F9AB0";
	string hex_res = set_to_hex_string(string_to_set<288>(res));
	cout << hex_res << endl;
}

void test() 
{
	test_simple_raplace_test1();
	test_simple_raplace_test2();
	test_simple_raplace_test3();
	test_simple_raplace_test4();
	//test_concatate_test1();
	//test_concatate_test2();
	//test_concatate_test3();
	//test_concatate_test4();
	//test_gamming_test1();
	//test_gamming_test2();
	//test_counter_test1();
	//test_counter_test2();
}

int main() 
{
	//test();
	bitset<128> x = hex_to_set<128>("B194BAC80A08F53B366D008E584A5DE4");
	bitset<256> t = hex_to_set<256>("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
	bitset<128> s = hex_to_set<128>("7ECDA4D01544AF8CA58450BF66D2E88A");
	// 0 - простая замена, 1 - сцепление блоков,
	// 2 - гаммирование с обратнойй связью, 3 - режим счетчика
	int mode = 0;
	int enc = 0; // 1 encrypt, 0 decrypt 
	//string input_file("input_file.txt");
	//string output_file("output_file.txt");
	
	string input_file("output_file.txt");
	string output_file("temp.txt");
	
	ofstream out(output_file);
	fstream in(input_file);
	string input_text((istreambuf_iterator<char>(in)), (istreambuf_iterator<char>()));
	string output_text;
	if (input_text.size() < 16) 
	{
		cout << "error, text length < 128 bit";
		return 0;
	}

	bitset<128> (*fun)(const bitset<128>&, const bitset<256>&);
	if (mode == 0) 
	{
		fun = enc ? F : F_1;
		output_text = simple_replace(input_text, t, fun);
	}
	else 
		if (mode == 1) 
		{
			fun = enc ? F : F_1;
			output_text = simple_replace(input_text, t, fun);
		}
	else 
		if (mode == 2) 
		{
			if (enc) 
				output_text = gamming_encrypt(input_text, t, s, F);
			else 
				output_text = gamming_decrypt(input_text, t, s, F);
		}
	else 
		{
			output_text = counter(input_text, t, s, F);
		}
	
	copy(output_text.begin(), output_text.end(), ostream_iterator<char>(out));
	
	
	// console
	cout << input_text << endl;
	cout << output_text << endl;

	cout << "hex" << endl;
	for (size_t i = 0; i < input_text.length(); i++) 
	{
		cout << hex << (int)(unsigned char)input_text[i];
	}

	cout << endl;

	for (size_t i = 0; i < output_text.length(); i++) 
	{
		cout << hex << (int)(unsigned char)output_text[i];
	}	  

	return 0;
}