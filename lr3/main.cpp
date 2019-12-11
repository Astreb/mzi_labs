#include "rsa.h"
#include <string>
#include <iostream>
#include <istream>
#include <fstream>
#include <iterator>

using namespace std;

/*
1. rsa public_key_filename private_key_filename keysize  -kg                     
2. rsa input_filename      output_filename      key_file -e(or -d) 

*/

int main(int argc, char** argv) {
	//mpz_class e, d, n;
	//tie(e, d, n) = rsa_generate_key(24);
	//cout << e.get_str() << endl;
	//cout << d.get_str() << endl;
	//cout << n.get_str() << endl;

	//string t = "dsfsdfasfaefewrqwrweqgfrg";
	//t[0] = 0xff;
	//t[1] = '\0';
	//t[2] = '\0';
	//t[3] = '\0';
	//t[4] = '\0';
	//cout << t << endl;
	//string c = rsa_encrypt(t, e, n);
	//cout << c << endl;
	//cout << rsa_decrypt(c, d, n) << endl
	//string s(2, '\0');
	//s[1] = 0xff;
	//mpz_t m;
	//mpz_init(m);
	//mpz_import(m, 2, 1, sizeof(char), 0, 0, s.data());
	//gmp_printf("%Zd\n", m);

	if (argc == 5) 
	{
		if (strcmp("-kg", argv[4]) == 0) 
		{
			string public_key_file = argv[1];
			string private_key_file = argv[2];
			int keysize = stoi(argv[3]);
			ofstream public_out(public_key_file);
			ofstream private_out(private_key_file);

			mpz_class e, d, n;
			tie(e, d, n) = rsa_generate_key(keysize);
			public_out << e.get_str() << endl << n.get_str();
			private_out << d.get_str() << endl << n.get_str();
			public_out.close();
			private_out.close();
		}
		else 
		{
			string input_file = argv[1];
			string output_file = argv[2];
			string key_file = argv[3];
			ifstream in(input_file, ifstream::binary);
			ofstream out(output_file, ofstream::binary);
			ifstream in_key(key_file);
			
			string ed_str, n_str, b_size_str;
			in_key >> ed_str;
			in_key >> n_str;
			in_key >> b_size_str;
			mpz_class ed(ed_str), n(n_str);
			int block_size = -1;
			if (!b_size_str.empty()) 
			{
				block_size = stoi(b_size_str);
			}
			string input_text((istreambuf_iterator<char>(in)), (istreambuf_iterator<char>()));
			string output_text;
			if ((strcmp("-e", argv[4]) == 0)) 
			{
				output_text = rsa_encrypt(input_text, ed, n, block_size);
			}
			else if ((strcmp("-d", argv[4]) == 0)) 
			{
				output_text = rsa_decrypt(input_text, ed, n, block_size);

			}
			copy(output_text.begin(), output_text.end(), ostream_iterator<char>(out));
			out.close();
			in.close();
			in_key.close();
		}
	}	
	return 0;
}
