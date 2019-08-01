#include <iostream>
#include <fstream>
#include <unordered_map>
#include "Present.h"
#include "MSEA.h"
#include "MSEA128.h"
#include "LEA.h"

// Struct which holds the input and output filestreams
struct filestreams {
	std::ifstream input;
	std::ofstream output;
	~filestreams() { input.close(); output.close(); }
};

// Function Prototypes
int selectedCipher(const std::string& parameter);
int selectedFunction(const std::string& parameter);
filestreams& openTestFile(const std::string& parameter, const int function);
uint8_t* retrieveKey(const char* keyFilename);
int retrieveDataFromFile(uint8_t* buffer, const int numBytes, std::ifstream& input);
int determineNonPaddingBytes(uint8_t* buffer, const int numBytes);
bool validPadding(uint8_t* buffer, const int value, const int index, const int numBytes);
void presentCipher(const int function, filestreams& files, uint8_t* masterKey);
void mseaCipher(const int function, filestreams& files, uint8_t* masterKey, const int numRounds);
void mseaStrictCipher(const int function, filestreams& files, uint8_t* masterKey, const int numRounds);
void leaCipher(const int function, filestreams& files, uint8_t* masterKey);

// Main function for Research project
int main(int argc, char* argv[]) {
	// Check number of parameters. Parameter 1 = Cipher, Parameter 2 = Encryption/Decryption, Parameter 3 = Test File, Parameter 4 = MSEA Rounds
	if (argc < 4) {
		std::cerr << "Incorrect number of parameters: <Cipher> <Function> <Test File> <MSEA Rounds>" << std::endl
			<< "<Cipher> = PRESENT, MSEA, or LEA" << std::endl
			<< "<Function> = ENCRYPTION or DECRYPTION" << std::endl
			<< "<Test File> = File to be encrypted or decrypted" << std::endl
			<< "<MSEA Rounds> = 1 to 63" << std::endl;
		return 1;
	}

	// Determine the selected cipher
	int cipher = selectedCipher(argv[1]);

	// Determine the selected cipher function
	int cipherFunction = selectedFunction(argv[2]);

	// Determine the selected test file and open it
	filestreams& files = openTestFile(argv[3], cipherFunction);

	// Get the symmetric key
	uint8_t* key = retrieveKey("key.key");

	// Perform the cipher function on the selected function
	switch (cipher) {
	case 0:
		presentCipher(cipherFunction, files, key);
		break;
	case 1:
		try {
			mseaCipher(cipherFunction, files, key, std::stoi(argv[4]));
		}
		catch (const std::invalid_argument &e) {
			std::cerr << "MSEA: " << e.what() << std::endl;
		}
		break;
	case 2:
		leaCipher(cipherFunction, files, key);
		break;
	default:
		try {
			mseaStrictCipher(cipherFunction, files, key, std::stoi(argv[4]));
		}
		catch (const std::invalid_argument &e) {
			std::cerr << "MSEASTRICT: " << e.what() << std::endl;
		}
	}

	// Perform cleanup
	delete[] key;
	delete &files;

	return 0;
}

int selectedCipher(const std::string& parameter) {
	int selectedCipher;
	if (parameter == "PRESENT")
		selectedCipher = 0;
	else if (parameter == "MSEA")
		selectedCipher = 1;
	else if (parameter == "LEA")
		selectedCipher = 2;
	else if (parameter == "MSEASTRICT")
		selectedCipher = 3;
	else {
		std::cerr << "Cipher must be PRESENT, MSEA, MSEASTRICT, or LEA" << std::endl;
		std::exit(2);
	}

	return selectedCipher;
}

int selectedFunction(const std::string& parameter) {
	int selectedFunction;
	if (parameter == "ENCRYPTION")
		selectedFunction = 0;
	else if (parameter == "DECRYPTION")
		selectedFunction = 1;
	else {
		std::cerr << "Function must be ENCRYPTION or DECRYPTION" << std::endl;
		std::exit(3);
	}

	return selectedFunction;
}

filestreams& openTestFile(const std::string& filename, const int function) {
	// Open the filestreams for input and output in binary mode
	std::string inputFilename, outputFilename;
	if (function == 0) {
		inputFilename = filename;
		outputFilename = filename + ".enc";
	}
	else {
		inputFilename = filename + ".enc";
		outputFilename = filename + ".dec";
	}
	filestreams* files = new filestreams();
	files->input = std::ifstream(inputFilename, std::fstream::binary);
	if (files->input.fail() == 1) {
		std::cerr << "Unable to open file " << inputFilename << std::endl;
		exit(4);
	}
	files->output = std::ofstream(outputFilename, std::fstream::trunc | std::fstream::binary);

	return *files;
}

uint8_t* retrieveKey(const char* keyFilename) {
	std::unordered_map<char, uint8_t> hex = {
		{'0', 0}, {'1', 1}, {'2', 2}, {'3', 3}, {'4', 4}, {'5', 5}, {'6', 6}, {'7', 7},
		{'8', 8}, {'9', 9}, {'A', 10}, {'B', 11}, {'C', 12}, {'D', 13}, {'E', 14}, {'F', 15},
		{'a', 10}, {'b', 11}, {'c', 12}, {'d', 13}, {'e', 14}, {'f', 15}
	};

	std::fstream keyFile(keyFilename, std::fstream::in);
	std::string hexKey;
	std::getline(keyFile, hexKey);

	uint8_t* binaryKey = new uint8_t[hexKey.size()];
	for (unsigned int i = 0, j = 0; i < hexKey.size(); i += 2, j++) {
		uint8_t temp = hex.at(hexKey[i]) << 4;
		temp |= hex.at(hexKey[i + 1]);
		binaryKey[j] = temp;
	}

	return binaryKey;
}

int retrieveDataFromFile(uint8_t* buffer, const int numBytes, std::ifstream& input) {
	int bytesProcessed = 0;

	char temp;
	while (bytesProcessed < numBytes && input.peek() != EOF) {
		input.get(temp);
		buffer[bytesProcessed] = temp;
		bytesProcessed++;
	}

	return bytesProcessed;
}

int determineNonPaddingBytes(uint8_t* buffer, const int numBytes) {
	int lastByte = (int)buffer[numBytes - 1];

	if (lastByte == 0 || lastByte > numBytes)
		return numBytes;

	bool valid = validPadding(buffer, lastByte, numBytes - 1, numBytes);

	return valid ? (numBytes - lastByte) : numBytes;
}

bool validPadding(uint8_t* buffer, const int value, const int index, const int numBytes) {
	// If the current index does equal value, then there is no padding
	if (buffer[index] != value)
		return false;
	// The values are the same, and if this is the last value, then padding is true
	if (index == (numBytes - value))
		return true;
	// Perform recursion to check the next value
	return validPadding(buffer, value, index - 1, numBytes);
}

void presentCipher(const int function, filestreams& files, uint8_t* masterKey) {
	Present present = Present();
	const int numBytes = BLOCK_SIZE / 8;
	bool generateRoundKeys = true;
	bool endOfFile = false;

	while (!endOfFile) {
		uint8_t data[numBytes];
		int bytesProcessed = retrieveDataFromFile(data, numBytes, files.input);

		// Will be used to add or remove padding
		if (files.input.peek() == EOF) {
			endOfFile = true;
			// Pad using method described in RFC1423 para 1.1
			// Value of each padding byte is the total number of padding bytes needed
			// to pad. 1 to 8
			if (function == 0) {
				int paddingValue = numBytes - bytesProcessed;
				for (int i = bytesProcessed; i < numBytes; i++)
					data[i] = (char)paddingValue;
			}
		}

		uint8_t* result;
		int binaryBytes = numBytes;
		if (function == 0)
			result = present.encryption(data, masterKey, generateRoundKeys);
		else
			result = present.decryption(data, masterKey, generateRoundKeys);

		// If this is decryption, remove the padding bytes
		if (function == 1 && endOfFile)
			binaryBytes = determineNonPaddingBytes(result, numBytes);

		files.output.write((char*)result, binaryBytes);

		// Round Cleanup
		delete[] result;
		if (generateRoundKeys)
			generateRoundKeys = false;
	}
}

void mseaCipher(const int function, filestreams& files, uint8_t* masterKey, const int numRounds) {
	const int plainBytes = 128 / 8,
		cipherBytes = 256 / 8;

	MSEA msea = MSEA();
	MSEA::CumulativeKey key = MSEA::CumulativeKey();	// Use the default 128-bit block

	uint8_t* swapKeyStr = retrieveKey("swap.key");	// Swap key is only 7 bits. The leftmost bit is not necessary
	uint16_t swapKey = (uint16_t)swapKeyStr[0] & 0x7F;
	delete[] swapKeyStr;
	key.setMasterKey(masterKey);
	key.setSwapKey(swapKey);

	bool generateRoundKeys = true;
	bool endOfFile = false;
	int numBytes = function == 0 ? plainBytes : cipherBytes,
		resBytes = function == 0 ? cipherBytes : plainBytes;
	uint8_t* data = new uint8_t[numBytes];

	while (!endOfFile) {
		int bytesProcessed = retrieveDataFromFile(data, numBytes, files.input);

		// Will be used to add or remove padding
		if (files.input.peek() == EOF) {
			endOfFile = true;
			// Pad using method described in RFC1423 para 1.1
			// Value of each padding byte is the total number of padding bytes needed
			// to pad. 1 to 8
			if (function == 0) {
				int paddingValue = numBytes - bytesProcessed;
				for (int i = bytesProcessed; i < numBytes; i++)
					data[i] = (char)paddingValue;
			}
		}

		uint8_t* result = nullptr;
		int binaryBytes = resBytes;
		if (function == 0)
			result = msea.encryption(data, key, numRounds, generateRoundKeys);
		else
			result = msea.decryption(data, key, numRounds, generateRoundKeys);

		// If this is decryption, remove the padding bytes
		if (function == 1 && endOfFile)
			binaryBytes = determineNonPaddingBytes(result, resBytes);

		files.output.write((char*)result, binaryBytes);

		// Round Cleanup
		delete[] result;
		if (generateRoundKeys)
			generateRoundKeys = false;
	}

	// End Cleanup
	delete[] data;
}

void mseaStrictCipher(const int function, filestreams& files, uint8_t* masterKey, const int numRounds) {
	MSEA128 msea = MSEA128();
	uint8_t* swapKeyStr = retrieveKey("swap.key");	// Swap key is only 7 bits. The leftmost bit is not necessary
	uint8_t swapKey = swapKeyStr[0] & 0x7F;
	delete[] swapKeyStr;

	const int plainBytes = MSEA_S_BLOCK_SIZE / 8,	// Plaintext block is 16 bytes
		cipherBytes = MSEA_S_KEY_SIZE / 8;	// Ciphertext block is 32 bytes

	bool generateRoundKeys = true;
	bool endOfFile = false;
	int numBytes = function == 0 ? plainBytes : cipherBytes,
		resBytes = function == 0 ? cipherBytes : plainBytes;
	uint8_t* data = new uint8_t[numBytes];

	while (!endOfFile) {
		//uint8_t* data = new uint8_t[numBytes];	// Must use new since it changes depending on encryption or decryption
		int bytesProcessed = retrieveDataFromFile(data, numBytes, files.input);

		// Will be used to add or remove padding
		if (files.input.peek() == EOF) {
			endOfFile = true;
			// Pad using method described in RFC1423 para 1.1
			// Value of each padding byte is the total number of padding bytes needed
			// to pad. 1 to 8
			if (function == 0) {
				int paddingValue = numBytes - bytesProcessed;
				for (int i = bytesProcessed; i < numBytes; i++)
					data[i] = (char)paddingValue;
			}
		}

		uint8_t* result = nullptr;
		int binaryBytes = resBytes;
		if (function == 0)
			result = msea.encryption(data, masterKey, swapKey, numRounds, generateRoundKeys);
		else
			result = msea.decryption(data, masterKey, swapKey, numRounds, generateRoundKeys);

		// If this is decryption, remove the padding bytes
		if (function == 1 && endOfFile)
			binaryBytes = determineNonPaddingBytes(result, resBytes);
		
		files.output.write((char*)result, binaryBytes);

		// Round Cleanup
		delete[] result;
		//delete[] data;
		if (generateRoundKeys)
			generateRoundKeys = false;
	}
	delete[] data;
}

void leaCipher(const int function, filestreams& files, uint8_t* masterKey) {
	LEA lea = LEA();
	//LEA::Key_128 key(masterKey);

	const int numBytes = LEA_BLOCK_SIZE / 8;
	bool generateRoundKeys = true;
	bool endOfFile = false;

	while (!endOfFile) {
		uint8_t data[numBytes];
		int bytesProcessed = retrieveDataFromFile(data, numBytes, files.input);

		// Will be used to add or remove padding
		if (files.input.peek() == EOF) {
			endOfFile = true;
			// Pad using method described in RFC1423 para 1.1
			// Value of each padding byte is the total number of padding bytes needed
			// to pad. 1 to 8
			if (function == 0) {
				int paddingValue = numBytes - bytesProcessed;
				for (int i = bytesProcessed; i < numBytes; i++)
					data[i] = (char)paddingValue;
			}
		}

		uint8_t* result = 0;
		int binaryBytes = numBytes;
		if (function == 0)
			result = lea.encryption_128(data, masterKey, generateRoundKeys);
		else
			result = lea.decryption_128(data, masterKey, generateRoundKeys);

		// If this is decryption, remove the padding bytes
		if (function == 1 && endOfFile)
			binaryBytes = determineNonPaddingBytes(result, numBytes);

		files.output.write((char*)result, binaryBytes);

		// Round Cleanup
		delete[] result;
		if (generateRoundKeys)
			generateRoundKeys = false;
	}
}
