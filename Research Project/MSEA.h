#pragma once
#ifndef MSEA_H
#define MSEA_H
#include <stdexcept>
#include <cmath>
#include <vector>

class MSEA {
public:
	//Used for the import of the master key, and generates setting for the
	//cipher. Settings are based on the selected block size
	class CumulativeKey {
	public:
		CumulativeKey(const int blck_size=128) {
			blockSize = blck_size >= 128 && blck_size <= 2048 && blck_size % 8 == 0 ? blck_size : throw std::range_error("Block size must be between 128 and 2048, and a multiple of 8.");
			masterKeySize = blockSize * 2;
			swapKeySize = (int)std::floor(std::log2(blockSize));
		}

		// Functions
		int getBlockSize(){ return blockSize; }
		int getMasterKeySize() { return masterKeySize; }
		int getSwapKeySize() { return swapKeySize; }
		uint8_t* getMasterKey() { return masterKey; }
		void setMasterKey(uint8_t* key) { masterKey = key; }
		uint16_t getSwapKey() { return swapKey; }
		void setSwapKey(const uint16_t key) { swapKey = key; }

	private:
		int blockSize,
			masterKeySize,
			swapKeySize;
		uint8_t* masterKey;
		uint16_t swapKey;
	};

	//Constructors/Destructors
	~MSEA() {
		for (unsigned int i = 0; i < roundKeys.size(); i++)
			delete[] roundKeys[i];
	}

	//Functions
	uint8_t* encryption(uint8_t* plaintext, CumulativeKey& key, const int numRounds, const bool generateKeys = true);
	uint8_t* decryption(uint8_t* ciphertext, CumulativeKey& key, const int numRounds, const bool generateKeys = true);

private:
	// Private functions
	void generateRoundKeys(const uint8_t* masterKey, const int keyByteSize, const int numRounds, const int ddrBits);

	// Helper functions
	uint8_t roundKey4bitSwap(uint8_t input);
	void keyDataDependentRotation(uint8_t* keyState, const int keyByteSize, const int ddrBits);
	void keyRotateLeft(uint8_t* data, const int keyByteSize, const int numRotations, const int ddrBits, const uint16_t limiter);
	void keyRotateRight(uint8_t* data, const int keyByteSize, const int numRotations, const int ddrBits, const uint16_t limiter);
	uint64_t keyLimiterAssistant(uint16_t limiter, const int numExtraBytes);
	uint8_t* expandMessage(uint8_t* plaintext, const int blockByteSize, const int keyByteSize);
	uint8_t* compressMessage(uint8_t* state, const int blockByteSize, const int keyByteSize);
	uint16_t messRotateLeft(uint16_t data, const int numRotations, const bool msb = false);
	uint16_t messRotateRight(uint16_t data, const int numRotations, const bool msb = false);
	void encryptionRound(uint8_t* state, uint8_t* key, const int stateByteSize, const int ddrBits);
	void decryptionRound(uint8_t* state, uint8_t* key, const int stateByteSize, const int ddrBits);
	int createSubBlocks(uint8_t* state, const int stateByteSize, std::array<uint8_t*, 4>& blocks, const bool unalignedBlocks);
	void modularAddition(uint8_t* lhs, uint8_t* rhs, const int blockByteSize);
	void modularSubtraction(uint8_t* lhs, uint8_t* rhs, const int blockByteSize);
	void blockXOR(uint8_t* lhs, uint8_t* rhs, const int blockByteSize);
	void roundDataDependentRotation(std::array<uint8_t *, 4U> &blocks, const int ddrBits, const int subBlockByteSize,
		const bool unalignedBlocks, const bool reverse = false);
	void roundRotateLeft(uint8_t* data, const int bytesToProcess, const int nonDDRBitsInLastByte, const int numRotations);
	void roundRotateRight(uint8_t* data, const int bytesToProcess, const int nonDDRBitsInLastByte, const int numRotations);
	int mergeBlocks(std::array<uint8_t*, 4> &blocks, std::array<uint8_t*, 2> &merged, const int subBlockByteSize, const bool unalignedBlocks, const bool encryption = true);
	void twoPhaseSwap(uint8_t* state, uint16_t swap, const int blockBitSize);
	uint8_t twoPhaseClearNonReleventBits(const uint8_t data, const int startBit, const int numBits);
	uint8_t twoPhaseClearReleventBits(const uint8_t data, const int startBit, const int numBits);

	// Private variables
	std::vector<uint8_t*> roundKeys;
};
#endif