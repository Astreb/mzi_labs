#include "elgamal.h"
#include <string>
#include <iostream>
#include <istream>
#include <fstream>
#include <iterator>
#include <sstream>

using namespace std;

/*
1. elgamal public_key_filename private_key_filename keysize  -kg
2. elgamal input_filename      output_filename      key_file -e(or -d)

publickeyfile:
	p
	g
	y

privatekeyfile:
	x
	p
*/

int main(int argc, char** argv) {
	//mpz_class p, g, y, x;
	//tie(p, g, y, x) = elg_generate_key(24);
	//cout << p.get_str() << endl;
	//cout << g.get_str() << endl;
	//cout << y.get_str() << endl;
	//cout << x.get_str() << endl;
	//cout << mpz_sizeinbase(p.get_mpz_t(), 2) << endl;

	//string t = "BSUIR135fjekaslfjsehafjksehajkf hjksaefhasejkhf jksehafjkahs fjgsrjhfgjhsdrghjsdrgjhgjhasrgîëûðâïîëðû\nûôîàëäîëàðãóêð3487éí897é89êàð48ö9éêï479é6íãóàïóêãïãøïãø";
	//t[0] = 0xff;
	//t[1] = '\0';
	//t[2] = '\0';
	//t[3] = '\0';
	//t[4] = '\0';
	//cout << t << endl;
	//string c = elg_encrypt(t, p, g, y);
	//cout << c << endl;
	//cout << elg_decrypt(c, p, x) << endl;
	//
	/*
	string t = "BSUIR135fjekaslfjsehafjksehajkf hjksaefhasejkhf jksehafjkahs fjgsrjhfgjhsdrghjsdrgjhgjhasrgîëûðâïîëðû\nûôîàëäîëàðãóêð3487éí897é89êàð48ö9éêï479é6íãóàïóêãïãøïãø";
	
	mpz_class p("614026145149816403910133"), g("2"), y("324637368551093721787613"), x("13805838539448443974363");
	string cl = elg_encrypt(t, p, g, y);
	string en = elg_decrypt(cl, p, x);
	cout << t << endl;
	cout << cl << endl;
	cout << en << endl;
	*/
	
	if (argc == 5) 
	{
		if (strcmp("-kg", argv[4]) == 0) 
		{
			string public_key_file = argv[1];
			string private_key_file = argv[2];
			int keysize = stoi(argv[3]);
			ofstream public_out(public_key_file);
			ofstream private_out(private_key_file);

			mpz_class p, g, y, x;
			tie(p, g, y, x) = elg_generate_key(keysize);
			public_out << p.get_str() << endl << g.get_str() << endl << y.get_str();
			private_out << p.get_str() << endl << x.get_str();
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

			string p_str, gx_str, y_str, b_size_str;
			in_key >> p_str;
			in_key >> gx_str;
			mpz_class p(p_str), gx(gx_str);

			string input_text((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
			string output_text;
			
			if ((strcmp("-e", argv[4]) == 0)) 
			{
				in_key >> y_str;
				in_key >> b_size_str;
				mpz_class y(y_str);
				int block_size = -1;
				if (!b_size_str.empty()) {
					block_size = stoi(b_size_str);
				}
				output_text = elg_encrypt(input_text, p, gx, y, block_size);
			}
			else 
				if ((strcmp("-d", argv[4]) == 0)) 
				{
					in_key >> b_size_str;
					int block_size = -1;
					if (!b_size_str.empty()) 
					{
						block_size = stoi(b_size_str);
					}

					output_text = elg_decrypt(input_text, p, gx, block_size);
				}
			//out.write(output_text.data(), output_text.size());
			copy(output_text.begin(), output_text.end(), ostream_iterator<char>(out));
			out.close();
			in.close();
			in_key.close();
		}
	}

	return 0;
}