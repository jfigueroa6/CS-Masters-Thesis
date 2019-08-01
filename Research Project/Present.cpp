#include <cstring>
#include "Present.h"

// Public Functions
/*
*	Public function used to perform encyption.
*/
uint8_t* Present::encryption(const uint8_t* plaintext, const uint8_t* masterKey, const bool generateKeys) {
	//Generate the round keys from the master_key if new keys should be generated.
	if (generateKeys)
		generateRoundKeys(masterKey);

	// Copy plaintext into state
	uint8_t* state = new uint8_t[BLOCK_SIZE / 8];
	std::memcpy(state, plaintext, BLOCK_SIZE / 8);

	//Perform the encryption rounds
	for (int i = 0; i < NUM_ROUNDS - 1; i++) {
		//Perform the add_round_key
		addRoundKey(state, roundKeys[i]);

		//Pass state bits through SBox (SBox Layer)
		sBoxLayer(state);

		// Move bits around (Permutation Layer)
		pLayer(state);
	}

	// Perform final add_round_key using final round key
	addRoundKey(state, roundKeys[NUM_ROUNDS - 1]);

	// Return ciphertext stored in state
	return state;
}

/*
*	Public function used to perform decryption.
*/
uint8_t* Present::decryption(const uint8_t* ciphertext, const uint8_t* masterKey, const bool generateKeys) {
	//Generate the round keys from the master_key if new keys should be generated.
	if (generateKeys)
		generateRoundKeys(masterKey);

	// Copy plaintext into state
	uint8_t* state = new uint8_t[BLOCK_SIZE / 8];
	std::memcpy(state, ciphertext, BLOCK_SIZE / 8);

	// Perform the initial add_round_key using round key 32
	addRoundKey(state, roundKeys[NUM_ROUNDS - 1]);

	// Perform the decryption rounds which is done in reverse
	for (int i = NUM_ROUNDS - 2; i >= 0; i--) {
		//Move bits around (Permutation Layer)
		pLayer(state, true);

		//Pass state bits through inverse SBox
		sBoxLayer(state, true);

		//Perform the add_round_key
		addRoundKey(state, roundKeys[i]);
	}
	
	return state;
}

// Private Functions
/*
*	Generates the round keys from the master key
*/
void Present::generateRoundKeys(const uint8_t* masterKey) {
	uint8_t keyRegister[KEY_SIZE / 8];
	std::memcpy(keyRegister, masterKey, KEY_SIZE / 8);

	// Generate Round Keys
	for (int round = 0; round < NUM_ROUNDS; round++) {
		// Step 1: Shift Left 61 Bits
		uint64_t tempKeyRegister[2];
		std::memcpy(&tempKeyRegister[0], keyRegister, sizeof(uint64_t));
		std::memcpy(&tempKeyRegister[1], &keyRegister[sizeof(uint64_t)], sizeof(uint64_t));
		uint64_t carry = tempKeyRegister[0] >> 3;
		tempKeyRegister[0] <<= 61;
		tempKeyRegister[0] |= tempKeyRegister[1] >> 3;
		tempKeyRegister[1] = (tempKeyRegister[1] << 61) | carry;
		std::memcpy(keyRegister, &tempKeyRegister[0], sizeof(uint64_t));
		std::memcpy(&keyRegister[sizeof(uint64_t)], &tempKeyRegister[1], sizeof(uint64_t));

		// Step 2 and 3: Pass the last byte through the SBox
		uint8_t left4Bits = keyRegister[(KEY_SIZE / 8) - 1] >> 4,
			right4Bits = keyRegister[(KEY_SIZE / 8) - 1] & 0x0F;
		left4Bits = sBox[left4Bits];
		right4Bits = sBox[right4Bits];
		keyRegister[(KEY_SIZE / 8) - 1] = (left4Bits << 4) | right4Bits;

		// Step 4: XOR Bits 62 - 66 with current round #
		// Bit 62 and 63 are in byte 7, and the rest are in byte 8
		uint8_t bitGroup = (keyRegister[7] & 0xC0) >> 6;
		bitGroup |= (keyRegister[8] & 0x03) << 2;
		bitGroup ^= round + 1;
		keyRegister[7] &= 0x3F;
		keyRegister[7] |= bitGroup << 6;
		keyRegister[8] &= 0xF8;
		keyRegister[8] |= bitGroup >> 2;
		
		//Save the leftmost 64 bits (bytes 8 - 15) as the round key
		std::memcpy(roundKeys[round], &keyRegister[8], 8);
		
	}
}

/*
*	Performs an XOR between the state and the round key
*/
void Present::addRoundKey(uint8_t* state, const uint8_t* roundKey) {
	// Perform XOR between state and round_key
	for (int i = 0; i < sizeof(uint64_t); i++)
		state[i] ^= roundKey[i];
}

/*
*	Performs the SBox layer of PRESENT on each byte.
*/
void Present::sBoxLayer(uint8_t* state, const bool inverse) {
	//SBox takes in 4 bits, so process each byte
	for (int i = 0; i < (BLOCK_SIZE / 8); i++) {
		uint8_t left4Bits = state[i] >> 4,
			right4Bits = state[i] & 0x0F;
		
		// If it's an inverse, use the inverse SBox else the normal SBox
		left4Bits = inverse ? invSBox[left4Bits] : sBox[left4Bits];
		right4Bits = inverse ? invSBox[right4Bits] : sBox[right4Bits];

		state[i] = (left4Bits << 4) | right4Bits;
		
	}
}

/*
*	Performs the permutation layer on each byte.
*/
void Present::pLayer(uint8_t* state, const bool inverse) {
	const uint8_t bitRetriever[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

	// Copy the state so it can be used for permutations, and clear the state for the new position
	uint8_t stateCopy[BLOCK_SIZE / 8];
	std::memcpy(stateCopy, state, (BLOCK_SIZE / 8));
	for (int i = 1; i < (BLOCK_SIZE / 8) - 1; i++)
		state[i] = 0;
	state[0] &= bitRetriever[0];
	state[7] &= bitRetriever[7];

	// Perform permutation on bits 1 - 62. Bits 0 and 63 stay in the same spot
	for (int i = 1; i < BLOCK_SIZE - 1; i++) {
		int bytePosition = i / 8,
			bitPosition = i % 8;

		// Get the new bit which will fill this position depending on if it's an inverse or normal permutation
		int newPos = inverse ? invPLayerPos[i] : pLayerPos[i];

		// Set the bit in the
		int srcBytePosition = newPos / 8,
			srcBitPosition = newPos % 8;
		uint8_t bitCopy = stateCopy[srcBytePosition];
		bitCopy &= bitRetriever[srcBitPosition];
		if (bitCopy != 0)
			state[bytePosition] |= bitRetriever[bitPosition];
	}
}