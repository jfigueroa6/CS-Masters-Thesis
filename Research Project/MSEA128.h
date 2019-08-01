#pragma once
#ifndef MSEA_STRICT_H
#define MSEA_STRICT_H
#define MSEA_S_BLOCK_SIZE 128
#define MSEA_S_BLOCK_BYTES	16
#define MSEA_S_KEY_SIZE	256
#define MSEA_S_KEY_BYTES	32
#define MSEA_S_DDR_BITS	7
#include <stdexcept>
#include <array>
#include <vector>

class MSEA128 {
public:
	//Functions
	uint8_t* encryption(uint8_t* plaintext, const uint8_t* masterKey, const uint8_t swapKey, const int numRounds, const bool generateKeys = true);
	uint8_t* decryption(uint8_t* ciphertext, const uint8_t* masterKey, const uint8_t swapKey, const int numRounds, const bool generateKeys = true);

private:
	// Private functions
	void generateRoundKeys(const uint8_t* masterKey, const int numRounds);

	// Helper functions
	uint8_t roundKey4bitSwap(uint8_t input);
	void keyRotateLeft(uint8_t* data, const int numRotations);
	void keyRotateRight(uint8_t* data, const int numRotations);
	void keyDataDependentRotation(uint8_t* keyState);
	uint8_t* expandMessage(uint8_t* plaintext);
	uint8_t* compressMessage(uint8_t* state);
	uint16_t messRotateLeft(uint16_t data, const int numRotations, const bool msb = false);
	uint16_t messRotateRight(uint16_t data, const int numRotations, const bool msb = false);
	void encryptionRound(uint8_t* state, const std::array<uint64_t, 4> key);
	void decryptionRound(uint8_t* state, const std::array<uint64_t, 4> key);
	uint64_t roundRotateLeft(uint64_t data, const int numRotations);
	uint64_t roundRotateRight(uint64_t data, const int numRotations);
	void modularAddition(uint64_t* lhs, uint64_t* rhs);
	void modularSubtracion(uint64_t* lhs, uint64_t* rhs);
	void twoPhaseSwap(uint8_t* state, uint8_t swap);
	uint8_t twoPhaseClearNonReleventBits(const uint8_t data, const int startBit, const int numBits);
	uint8_t twoPhaseClearReleventBits(const uint8_t data, const int startBit, const int numBits);

	// Private variables
	std::vector<std::array<uint64_t, 4>> roundKeys;
};

#endif