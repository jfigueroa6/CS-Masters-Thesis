#pragma once
#ifndef RESEARCH_AES_H
#define	RESEARCH_AES_H
#include <string>
#include <fstream>
#include <cryptopp700/aes.h>

class ResearchAES {
public:
	static std::string encryption(const std::string& plaintext_file, const std::string& ciphertext_file, CryptoPP::byte key[]);
	static std::string decryption(const std::string& ciphertext_file, const std::string& plaintext_file, CryptoPP::byte key[]);
};

#endif // !RESEARCH_AES_H

