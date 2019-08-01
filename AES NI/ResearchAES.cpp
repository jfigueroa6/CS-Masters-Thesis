#include <iostream>
#include "ResearchAES.h"
#include <cryptopp700/modes.h>
#include <cryptopp700/files.h>
#include <cryptopp700/filters.h>


std::string ResearchAES::encryption(const std::string& plaintext_file, const std::string& ciphertext_file, CryptoPP::byte key[]) {
	//Use ECB Mode
	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption aes;
	aes.SetKey(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	try {
		CryptoPP::FileSource(
			plaintext_file.c_str(),	//File to encrypt
			true,					//Encrypt the entire file
			new CryptoPP::StreamTransformationFilter(
				aes,
				new CryptoPP::FileSink(ciphertext_file.c_str())
			)
		);
	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Exception Caught:\n" << e.what() << std::endl;
	}

	return ciphertext_file;
}

std::string ResearchAES::decryption(const std::string& ciphertext_file, const std::string& plaintext_file, CryptoPP::byte key[]) {
	//Use ECB Mode
	CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption aes;
	aes.SetKey(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	try {
		CryptoPP::FileSource(
			ciphertext_file.c_str(),	//File to decrypt
			true,
			new CryptoPP::StreamTransformationFilter(
				aes,
				new CryptoPP::FileSink(plaintext_file.c_str())
			)
		);
	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Exception Caught:\n" << e.what() << std::endl;
	}

	return plaintext_file;
}
