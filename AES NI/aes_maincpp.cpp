#include <iostream>
#include <string>
#include <cryptopp700/osrng.h>
#include "ResearchAES.h"

struct Files {
	std::string input,
		output;
};

// Function protoptypes
int selectedFunction(const std::string& parameter);
Files* determineTestFiles(const std::string& parameter, const int function);
CryptoPP::byte* retrieveKey(const char* keyFilename);


// Main function for Research project
int main(int argc, char* argv[]) {
	// Check the number of parameters, parameter 1 = Encryption/Decryption, parameter 2 = Test file
	if (argc != 3) {
		std::cerr << "Incorrect number of parameters: <Function> <Test File>\n"
			<< "<Function> = ENCRYPTION or DECRYPTION\n"
			<< "<Test File> = File to be encrypted or decrypted" << std::endl;
		return 1;
	}

	// Determine the selected AES function
	int cipherFunction = selectedFunction(argv[1]);

	// Determine the selected test file
	Files* files = determineTestFiles(argv[2], cipherFunction);

	// Retrieve the key from the key file
	CryptoPP::byte* key = retrieveKey("key.key");

	// Perform the encryption/decryption
	switch (cipherFunction) {
	case 0:
		ResearchAES::encryption(files->input, files->output, key);
		break;
	default:
		ResearchAES::decryption(files->input, files->output, key);
		break;
	}

	// Cleanup
	delete files;
	delete[] key;

	return 0;
}

int selectedFunction(const std::string& parameter) {
	int selectedFunction;
	if (parameter == "ENCRYPTION")
		selectedFunction = 0;
	else if (parameter == "DECRYPTION")
		selectedFunction = 1;
	else {
		std::cerr << "Function must be ENCRYPTION or DECRYPTION" << std::endl;
		std::exit(1);
	}

	return selectedFunction;
}

Files* determineTestFiles(const std::string& filename, const int function) {
	// Open the filestreams for input and output in binary mode
	Files* files = new Files();
	if (function == 0) {
		files->input = filename;
		files->output = filename + ".enc";
	}
	else {
		files->input = filename + ".enc";
		files->output = filename + ".dec";
	}

	return files;
}

CryptoPP::byte* retrieveKey(const char* keyFilename) {
	std::ifstream keyFile(keyFilename);
	std::string hexKey;
	std::getline(keyFile, hexKey);

	// Create and initialize key to 0
	CryptoPP::byte* key = new CryptoPP::byte[CryptoPP::AES::DEFAULT_KEYLENGTH]; // Only using 128-bit keys
	for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++)
		key[i] = 0;
	
	for (int i = hexKey.size() - 2, j = CryptoPP::AES::DEFAULT_KEYLENGTH - 1; i >= 0; i -= 2, j--)
		key[j] = (CryptoPP::byte)std::stoi(hexKey.substr(i, 2), nullptr, 16);

	return key;
}