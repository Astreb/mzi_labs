#include "des.h"
#include <string>
#include <iostream>
#include <istream>
#include <fstream>
using namespace std;


bitset<64> des3_encrypt_block(DES & des1, DES & des2, bitset<64>& block) {
	return des1.encrypt_block(des2.decrypt_block(des1.encrypt_block(block)));
}

bitset<64> des3_decrypt_block(DES & des1, DES & des2, bitset<64>& block) {
	return des1.decrypt_block(des2.encrypt_block(des1.decrypt_block(block)));
}

bitset<64> des2_encrypt_block(DES & des1, DES & des2, bitset<64>& block) {
	return des2.encrypt_block(des1.encrypt_block(block));
}

bitset<64> des2_decrypt_block(DES & des1, DES & des2, bitset<64>& block) {
	return des1.decrypt_block(des2.decrypt_block(block)); 
}

bitset<64> des_encrypt_block(DES & des1, DES & des2, bitset<64> & block) {
	return des1.encrypt_block(block);
}

bitset<64> des_decrypt_block(DES & des1, DES & des2, bitset<64> & block) {
	return des1.decrypt_block(block);
}

string des2_3(const string& text, const string& key1, const string& key2, bitset<64> (*f)(DES &, DES &, bitset<64>&)) {
	int blocks_count = (text.length() + 7) / 8;
	string input = text;
	input.resize(blocks_count * 8);
	string output(blocks_count * 8, '\0');
	DES des1(key1), des2(key2);

	for (int b = 0; b < blocks_count; b++)
	{
		bitset<64> block;
		for (int i = 0; i < 8; i++)
			for (int j = 0; j < 8; j++)
				block[i * 8 + j] = input[b * 8 + i] & (1 << (7 - j));

		bitset<64> coded_block = f(des1, des2, block);

		for (int i = 0; i < 8; i++)
			for (int j = 0; j < 8; j++)
				output[b * 8 + i] |= ((coded_block[i * 8 + j] ? 1 : 0) << (7 - j));
	}

	return output;
}


int main() {
	int des = 3; // 0 - des2, 1 - des3
	bool mode = true; // true - encrypt, false - decrypt
	string key1("12345678");
	string key2("abcdefg");
	string input_file("input_file.txt");
	string output_file("output_file.txt");
	//string input_file("output_file.txt");
	//string output_file("temp.txt");
	ofstream out(output_file);
	fstream in(input_file);
	string input_text((istreambuf_iterator<char>(in)), (istreambuf_iterator<char>()));
	string output_text;
	bitset<64>(*f)(DES&, DES&, bitset<64>&);

	if (des == 0) 
	{
		if (mode == true)
			f = des2_encrypt_block;
		else 
			f = des2_decrypt_block;
	}
	else 
	{
		if (mode == true)
			f = des3_encrypt_block;
		else 
			f = des3_decrypt_block;
	}

	if (des == 3) 
	{
		if (mode == true)
			f = des_encrypt_block;
		else 
			f = des_decrypt_block;
	}

	output_text = des2_3(input_text, key1, key2, f);
	copy(output_text.begin(), output_text.end(), ostream_iterator<char>(out));
	out.close();
	in.close();
	//out << output_text;
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