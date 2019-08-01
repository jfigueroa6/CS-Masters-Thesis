#pragma once
#ifndef PRESENT_H
#define PRESENT_H
#define	HEX_BITS 4
#define BLOCK_SIZE 64
#define KEY_SIZE 128
#define NUM_ROUNDS 32
#include <bitset>
#include <unordered_map>
#include <array>

// Class that implements the PRESENT cipher
class Present {
public:
	// Public Type Definitions
	typedef std::bitset<BLOCK_SIZE> Block;
	typedef std::bitset<KEY_SIZE> Key;

	// Functions
	uint8_t* encryption(const uint8_t* plaintext, const uint8_t* masterKey, const bool generateKeys=true);
	uint8_t* decryption(const uint8_t* ciphertext, const uint8_t* masterKey, const bool generateKeys=true);

private:
	//Type Definitons
	/*typedef std::bitset<HEX_BITS> Hex;
	typedef std::unordered_map<Hex, Hex, std::hash<Hex>> HashMap;*/

	//Functions
	void generateRoundKeys(const uint8_t* masterKey);
	void addRoundKey(uint8_t* state, const uint8_t* roundKey);
	void sBoxLayer(uint8_t* state, const bool inverse=false);
	void pLayer(uint8_t* state, const bool inverse=false);

	// Variables
	std::array<uint8_t[8], NUM_ROUNDS> roundKeys;
	const std::array<uint8_t, 16> sBox = { 12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2 };
	const std::array<uint8_t, 16> invSBox = { 5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10 };

	const int pLayerPos[64] = { 0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
		8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63
	};
	const int invPLayerPos[64] = { 0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,1,5,9,13,17,21,25,29,33,37,41,45,49,53,
		57,61,2,6,10,14,18,22,26,30,34,38,42,46,50,54,58,62,3,7,11,15,19,23,27,31,35,39,43,47,51,55,59,63
	};
};

#endif
