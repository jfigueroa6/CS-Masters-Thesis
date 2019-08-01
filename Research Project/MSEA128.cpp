#include "MSEA128.h"
#include <cstring>

/*
*	Public function used to start the encryption process.
*/
uint8_t* MSEA128::encryption(uint8_t* plaintext, const uint8_t* masterKey, const uint8_t swapKey, const int numRounds, const bool generateKeys) {
	//Generate the round keys based on the given number of rounds, and if the generate_keys parameter is set
	if (generateKeys)
		generateRoundKeys(masterKey, numRounds);

	// Expand the message
	uint8_t* state = expandMessage(plaintext);

	// Perform rounds
	for (int i = 0; i < numRounds; i++)
		encryptionRound(state, roundKeys[i]);

	// Perform 2-phase swap
	twoPhaseSwap(state, swapKey);

	return state;
}

/*
*	Public function used to start the decryption process.
*/
uint8_t * MSEA128::decryption(uint8_t * ciphertext, const uint8_t* masterKey, const uint8_t swapKey, const int numRounds, const bool generateKeys) {
	//Generate the round keys based on the given number of rounds, and if the generate_keys parameter is set
	if (generateKeys)
		generateRoundKeys(masterKey, numRounds);

	uint8_t* state = ciphertext;

	// Perform 2-phase swap
	twoPhaseSwap(state, swapKey);

	// Perform rounds
	for (int i = numRounds - 1; i >= 0; i--)
		decryptionRound(state, roundKeys[i]);

	return compressMessage(state);
}

/*
*	Generates the round key based on the key, key size, number of rounds, and the DDR bits.
*/
void MSEA128::generateRoundKeys(const uint8_t* masterKey, const int numRounds) {
	// Copy the master key into an key sate to be used for round key generation
	uint8_t keyState[MSEA_S_KEY_BYTES];
	std::memcpy(keyState, masterKey, MSEA_S_KEY_BYTES);
	//for (int i = 0; i < (MSEA_S_KEY_BYTES); i++)
	//	keyState[i] = masterKey[i];

	// Set round keys to the number of selected rounds
	roundKeys.resize(numRounds);

	for (int i = 0; i < numRounds; i++) {
		// Process from MSB to LSB a single byte at a time
		for (int i = 0; i < (MSEA_S_KEY_BYTES); i++) {
			// Performs 4-bit swap
			keyState[i] = roundKey4bitSwap(keyState[i]);
		}

		// Perform data dependent rotation
		keyDataDependentRotation(keyState);

		// Save the round key
		std::array<uint64_t, 4> roundKey;
		for (int j = 0, k = 0; j < 4; j++, k += sizeof(uint64_t))
			std::memcpy(&roundKey[j], &keyState[k], sizeof(uint64_t));
		roundKeys[i] = roundKey;
	}
}

/*
*	Performs the key 4-bit swap task. This is performed per byte.
*/
uint8_t MSEA128::roundKey4bitSwap(uint8_t input) {
	// Swap the left 4 bits with the right 4 bits
	uint8_t swapResult = (input << 4) | ((input >> 4));

	// Rotate the new left 4 bits to the left. This rotates only among the left 4 bits
	uint8_t tempLeft = swapResult & 0xF0;
	tempLeft = (tempLeft << 3) | ((tempLeft >> 1) & 0xF0);
	// Rotate the new right 4 bits to the right. This rotates only among the right 4 bits
	uint8_t tempRight = swapResult & 0x0F;
	tempRight = (tempRight >> 3) | ((tempRight << 1) & 0x0F);
	tempRight = ~tempRight & 0x0F;	// Only maintain the right 4 bits

	// Return the merged left and right back into a byte
	return tempLeft | tempRight;
}

/*
*	Rotates the key state to left using the information in the DDR bits.
*/
void MSEA128::keyRotateLeft(uint8_t* data, const int numRotations) {
	uint64_t groups[4];
	for (int i = 0, j = 0; i < 4; i++, j += sizeof(uint64_t))
		std::memcpy(&groups[i], &data[j], sizeof(uint64_t));

	int numRotationsRemaining = numRotations;

	while (numRotationsRemaining > 0) {
		// Process each group 64 bits. Only shift right a max of 57 bits since this is the max amount allowed in the
		// last group. The remaining 7 bits are the bits used for rotation information
		int roundNumRotations = numRotationsRemaining > 57 ? 57 : numRotationsRemaining;
		uint64_t carry = 0;

		for (int i = 0; i < 4; i++) {
			int maxSize = i == 3 ? 57 : sizeof(uint64_t);
			uint64_t tempCarry = (groups[i] >> (maxSize - roundNumRotations));
			groups[i] = (groups[i] << roundNumRotations) | carry;
			carry = tempCarry;
		}

		// Insert carry into the first group to complete the rotation
		groups[0] |= carry;

		numRotationsRemaining -= roundNumRotations;
	}

	for (int i = 0, j = 0; i < 4; i++, j += sizeof(uint64_t))
		std::memcpy(&data[j], &groups[i], sizeof(uint64_t));
}

/*
*	Rotates the key state to right using the information in the DDR bits.
*/
void MSEA128::keyRotateRight(uint8_t* data, const int numRotations) {
	uint64_t groups[4];
	for (int i = 0, j = 0; i < 4; i++, j += sizeof(uint64_t))
		std::memcpy(&groups[i], &data[j], sizeof(uint64_t));

	int numRotationsRemaining = numRotations;

	while (numRotationsRemaining > 0) {
		// Process each group 64 bits. Only shift right a max of 57 bits since this is the max amount allowed in the
		// last group. The remaining 7 bits are the bits used for rotation information
		int roundNumRotations = numRotationsRemaining > 57 ? 57 : numRotationsRemaining;
		uint64_t carry = 0;

		for (int i = 0; i < 4; i++) {
			int maxSize = i == 3 ? 57 : 64;
			uint64_t tempCarry = (groups[i] << (maxSize - roundNumRotations));
			groups[i] = (groups[i] >> roundNumRotations) | carry;
			carry = tempCarry;
		}

		// Insert carry into the first group to complete the rotation
		groups[0] |= carry;

		numRotationsRemaining -= roundNumRotations;
	}

	for (int i = 0, j = 0; i < 4; i++, j += sizeof(uint64_t))
		std::memcpy(&data[j], &groups[i], sizeof(uint64_t));
}

/*
*	Performs Data Dependent Rotation on the key state. THis version is specific to the key generation.
*/
void MSEA128::keyDataDependentRotation(uint8_t* keyState) {
	// Get the rotation info. The rotation direction is msb of last byte. Rotation number is bits 6 - 1.
	int rotationDirection = keyState[MSEA_S_KEY_BYTES - 1] & 0x80,
		rotationNumber = keyState[MSEA_S_KEY_BYTES - 1] & 0x7E;

	uint8_t temp = keyState[MSEA_S_KEY_BYTES - 1] & 0x8E;	// Holds the rotation info and removes it from the keyState so it's not lost
	keyState[MSEA_S_KEY_BYTES - 1] &= 0x01;		//Only need the LSB of the last byte

	// Use rotation direction to apply correct rotation (0 = Right, 1 = Left)
	if (rotationDirection == 0)
		keyRotateRight(keyState, rotationNumber);
	else
		keyRotateLeft(keyState, rotationNumber);

	// Restore the rotation info back into the last byte
	keyState[MSEA_S_KEY_BYTES - 1] |= temp;
}

/*
*	Performs the expand message stage of the encryption process. This expands each byte into 2 bytes.
*/
uint8_t * MSEA128::expandMessage(uint8_t * plaintext) {
	uint8_t* result = new uint8_t[MSEA_S_KEY_BYTES];

	// Work on a byte which will be expaned to 2 bytes
	for (int i = 0, j = 0; i < MSEA_S_BLOCK_BYTES; i++, j += 2) {
		// Expand byte into 16 bits.
		uint16_t intermediate = plaintext[i];
		intermediate = (intermediate << 8) | plaintext[i];
		intermediate = (intermediate << 4) | (intermediate >> 12);

		// Perform DDR using right 4 bits
		int rotationDirection = intermediate & 0x0008,
			rotationInfo = intermediate & 0x0007;
		if (rotationDirection == 0)
			intermediate = messRotateRight(intermediate, rotationInfo);
		else
			intermediate = messRotateLeft(intermediate, rotationInfo);

		// Perform DDR using left 4 bits
		rotationDirection = intermediate & 0x8000;
		rotationInfo = (intermediate & 0x7000) >> 12;
		if (rotationDirection == 0)
			intermediate = messRotateRight(intermediate, rotationInfo, true);
		else
			intermediate = messRotateLeft(intermediate, rotationInfo, true);

		// One's complement intermediate and store in result
		intermediate = ~intermediate;
		//std::cout << intermediate << " ";
		std::memcpy(&result[j], &intermediate, sizeof(uint16_t));
	}
	//std::cout << std::endl;

	return result;
}

/*
*	Performs the compress message stage of the decryption process. This reduces 2 bytes into
*	a byte.
*/
uint8_t * MSEA128::compressMessage(uint8_t * state) {
	uint8_t* result = new uint8_t[MSEA_S_BLOCK_BYTES];

	// Work on two bytes which will be compressed to 1 byte
	for (int i = 0, j = 0; i < MSEA_S_BLOCK_BYTES; i++, j += 2) {
		// Copy two bytes into intermediate and One's complement
		uint16_t intermediate;
		std::memcpy(&intermediate, &state[j], sizeof(uint16_t));
		//std::cout << intermediate << " ";
		intermediate = ~intermediate;

		// Perform DDR using left 4 bits
		int rotationDirection = intermediate & 0x8000,
			rotationInfo = (intermediate & 0x7000) >> 12;
		if (rotationDirection == 0)
			intermediate = messRotateLeft(intermediate, rotationInfo, true);
		else
			intermediate = messRotateRight(intermediate, rotationInfo, true);

		// Perform DDR using right 4 bits
		rotationDirection = intermediate & 0x0008;
		rotationInfo = intermediate & 0x0007;
		if (rotationDirection == 0)
			intermediate = messRotateLeft(intermediate, rotationInfo);
		else
			intermediate = messRotateRight(intermediate, rotationInfo);

		// Only need the middle bits since those are the original plaintext
		intermediate >>= 4;
		result[i] = intermediate;
	}
	//std::cout << std::endl;

	return result;
}

/*
*	Performs a DDR left rotation on 16-bit message. It is limited to the data portion of the
*	16-bits.
*/
uint16_t MSEA128::messRotateLeft(uint16_t data, const int numRotations, const bool msb) {
	uint16_t limiter = msb ? 0x0FFF : 0xFFF0,	// Used to ignore the rotation info bits.
		rotationInfo = data & (msb ? 0xF000 : 0x000F),
		result;

	result = data & limiter;
	result = ((result << numRotations) | ((result >> (12 - numRotations)) & limiter)) & limiter;


	return result | rotationInfo;
}

/*
*	Performs a DDR right rotation on 16-bit message. It is limited to the data portion of the
*	16-bits.
*/
uint16_t MSEA128::messRotateRight(uint16_t data, const int numRotations, const bool msb) {
	uint16_t limiter = msb ? 0x0FFF : 0xFFF0,	// Used to ignore the rotation info bits.
		rotationInfo = data & (msb ? 0xF000 : 0x000F),
		result;

	result = data & limiter;
	result = ((result >> numRotations) | ((result << (12 - numRotations)) & limiter)) & limiter;


	return result | rotationInfo;
}

/*
*	Performs a single encryption round. The result is stored in the state.
*/
void MSEA128::encryptionRound(uint8_t* state, const std::array<uint64_t, 4> key) {
	// Divide state into 4 64-bit blocks
	std::array<uint64_t, 4> blocks;
	for (int i = 0, j = 0; i < 4; i++, j += sizeof(uint64_t))
		std::memcpy(&blocks[i], &state[j], sizeof(uint64_t));

	// Perform modular addition
	blocks[3] += blocks[2];
	blocks[2] += blocks[1];
	blocks[1] += blocks[0];
	blocks[0] += blocks[3];

	// Perform Data Dependent Rotation based on last 7 bits
	for (int i = 0; i < blocks.size(); i++) {
		int rotationData = ((blocks[i] << 7) | (blocks[i] >> 57)) & 0x4F, // Only want the last 7 bits, ignore the rest
			rotationDirection = rotationData & 0x40,
			rotationInfo = rotationData & 0x3F;

		if (rotationDirection == 0)
			blocks[i] = roundRotateRight(blocks[i], rotationInfo);
		else
			blocks[i] = roundRotateLeft(blocks[i], rotationInfo);
	}

	// Perform XOR operations
	blocks[0] ^= key[0];
	blocks[1] ^= blocks[0] ^ key[1];
	blocks[2] ^= blocks[1] ^ key[2];
	blocks[3] ^= blocks[2] ^ key[3];

	// Concatenate groups
	uint64_t blockE[2] = {blocks[2], blocks[0]}, 
		blockF[2] = {blocks[3], blocks[1]};

	// Perform final XOR and modular addition
	blockF[0] ^= blockE[0];
	blockF[1] ^= blockE[1];
	modularAddition(blockE, blockF);

	// Concatenate blocks E and F with F first
	uint64_t result[4] = { blockF[0], blockF[1], blockE[0], blockE[1] };

	// Place result back into state
	for (int i = 0, j = 0; i < 4; i++, j += sizeof(uint64_t))
		std::memcpy(&state[j], &result[i], sizeof(uint64_t));
}

/*
*	Performs a single decryption round. The result is stored in the state.
*/
void MSEA128::decryptionRound(uint8_t * state, const std::array<uint64_t, 4> key) {
	// Break result into blocks E and F
	uint64_t blockE[2], blockF[2];
	std::memcpy(&blockF[0], state, sizeof(uint64_t));
	std::memcpy(&blockF[1], state + sizeof(uint64_t), sizeof(uint64_t));
	std::memcpy(&blockE[0], state + (2 * sizeof(uint64_t)), sizeof(uint64_t));
	std::memcpy(&blockE[1], state + (3 * sizeof(uint64_t)), sizeof(uint64_t));

	// Perform modular subtraction and XOR
	modularSubtracion(blockE, blockF);
	blockF[0] ^= blockE[0];
	blockF[1] ^= blockE[1];

	uint64_t blocks[4] = { blockE[1], blockF[1], blockE[0], blockF[0] };

	// Perform XOR operations
	blocks[3] ^= blocks[2] ^ key[3];
	blocks[2] ^= blocks[1] ^ key[2];
	blocks[1] ^= blocks[0] ^ key[1];
	blocks[0] ^= key[0];

	// Perform Data Dependent Rotation based on last 7 bits
	for (int i = 0; i < 4; i++) {
		int rotationData = ((blocks[i] << 7) | (blocks[i] >> 57)) & 0x4F, // Only want the last 7 bits, ignore the rest
			rotationDirection = rotationData & 0x40,
			rotationInfo = rotationData & 0x3F;

		if (rotationDirection == 0)
			blocks[i] = roundRotateLeft(blocks[i], rotationInfo);
		else
			blocks[i] = roundRotateRight(blocks[i], rotationInfo);
	}

	// Perform modular subtraction
	blocks[0] -= blocks[3];
	blocks[1] -= blocks[0];
	blocks[2] -= blocks[1];
	blocks[3] -= blocks[2];

	for (int i = 0, j = 0; i < 4; i++, j += sizeof(uint64_t))
		std::memcpy(&state[j], &blocks[i], sizeof(uint64_t));
}

/*
*	Performs a left data dependent rotation on a subblock.
*/
uint64_t MSEA128::roundRotateLeft(uint64_t data, const int numRotations) {
	uint64_t limiter = 0x01FFFFFFFFFFFFFF,
		rotationInfo = data & 0xFE00000000000000,
		result;

	result = data & limiter;
	result = ((result << numRotations) | ((result >> (57 - numRotations)) & limiter)) & limiter;

	return result | rotationInfo;
}

/*
*	Performs a right data dependent rotation on a subblock.
*/
uint64_t MSEA128::roundRotateRight(uint64_t data, const int numRotations) {
	uint64_t limiter = 0x01FFFFFFFFFFFFFF,
		rotationInfo = data & 0xFE00000000000000,
		result;

	result = data & limiter;
	result = ((result >> numRotations) | ((result << (57 - numRotations)) & limiter)) & limiter;

	return result | rotationInfo;
}

/*
*	Performs modular addition with response in the LHS parameter. Algorithm created using the following:
*	https://bisqwit.iki.fi/story/howto/bitmath/#UsingBitwiseOperationsWithXor
*/
void MSEA128::modularAddition(uint64_t* lhs, uint64_t* rhs) {
	int carry = 0;
	for (int i = 0; i < 2; i++) {
		lhs[i] += rhs[i] + carry;
		// If the result in lhs[i] is less than the rhs operand, then that means the result overflowed, so set carry.
		carry = lhs[i] < rhs[i] ? 1 : 0;
	}
}

/*
*	Performs modular subtraction with response in the LHS parameter. Algorithm created using the following:
*	https://bisqwit.iki.fi/story/howto/bitmath/#UsingBitwiseOperationsWithXor
*/
void MSEA128::modularSubtracion(uint64_t * lhs, uint64_t * rhs) {
	int carry = 0;
	for (int i = 0; i < 2; i++) {
		uint64_t original = lhs[i];
		lhs[i] -= rhs[i] + carry;
		// If the result in lhs[i] is greater than the original value, then the result underflowed, so set carry.
		carry = lhs[i] > original ? 1 : 0;
	}
}

/*
*	Performs the two phase swap stage.
*/
void MSEA128::twoPhaseSwap(uint8_t* state, uint8_t swap) {
	// Skip if swap is 0, or else it'll never do anything
	if (swap == 0)
		return;

	// Flip every ith bit determined by swap
	const uint8_t bitRetriever[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
	for (int i = swap - 1; i < MSEA_S_KEY_SIZE; i += swap) {
		int j = (i - 1) / 8,
			k = (i - 1) % 8;
		uint8_t bit = state[j] & bitRetriever[k],
			flipped = ~bit & bitRetriever[k];
		if (flipped == 0)
			state[j] -= bit;
		else
			state[j] += flipped;
	}

	// Swap every i bits with neighboring i bits; i determined by swap
	for (int i = 0; i < MSEA_S_KEY_SIZE - (swap * 2); i += (swap * 2)) {
		int leftBytes = (i / 8),
			leftBit = i % 8,
			rightBytes = ((i + swap) / 8),
			rightBit = (i + swap) % 8,
			count = 0;

		int takeInBits = swap;
		while (count < swap) {
			// Get how many bits will be pulled in by the left and right. Used in the cases where a side requires
			// more bits than the current 32 bits have.
			int leftNumBits = leftBit + takeInBits < 8 ? takeInBits : 8 - leftBit,
				rightNumBits = rightBit + takeInBits < 8 ? takeInBits : 8 - rightBit;

			// Determine which side took in the least amount of bits, and use that to limit the swap to only
			// the smaller value.
			int smallestNumBits = leftNumBits < rightNumBits ? leftNumBits : rightNumBits;
			uint8_t left = state[leftBytes],
				right = state[rightBytes],
				temp = right;
			left = twoPhaseClearNonReleventBits(left, leftBit, smallestNumBits);
			right = twoPhaseClearNonReleventBits(right, rightBit, smallestNumBits);

			// Move bits into their new positions
			left = leftBit < rightBit ? (left >> (rightBit - leftBit)) : (left << (leftBit - rightBit));
			right = rightBit < leftBit ? (right >> (leftBit - rightBit)) : (right << (rightBit - leftBit));

			// Swap bits
			temp = twoPhaseClearReleventBits(temp, rightBit, smallestNumBits);
			temp |= left;
			state[rightBytes] = temp;
			temp = state[leftBytes];
			temp = twoPhaseClearReleventBits(temp, leftBit, smallestNumBits);
			temp |= right;
			state[leftBytes] = temp;

			count += smallestNumBits;
			takeInBits -= smallestNumBits;
			leftBytes = ((i + smallestNumBits) / 8),
			leftBit = (i + smallestNumBits) % 8;
			rightBytes = ((i + swap + smallestNumBits) / 8),
			rightBit = (i + swap + smallestNumBits) % 8;
		}
	}
}

/*
*	Clears the bits that are not relevent for the two phase swap
*/
uint8_t MSEA128::twoPhaseClearNonReleventBits(const uint8_t data, const int startBit, const int numBits) {
	uint8_t result = data;
	result <<= startBit;
	result >>= startBit;
	result >>= (8 - (startBit + numBits));
	result <<= (8 - (startBit + numBits));
	return result;
}

/*
*	Clears the bits that are relevent for the two phase swap. It is used to clear the destination
*	for the swap.
*/
uint8_t MSEA128::twoPhaseClearReleventBits(const uint8_t data, const int startBit, const int numBits) {
	uint8_t tempA = data, tempB = data;
	int numRotations = startBit + numBits;
	if (numRotations == 8)
		tempA = 0;
	else {
		tempA <<= numRotations;
		tempA >>= numRotations;
	}

	numRotations = (8 - (startBit + numBits)) + numBits;
	if (numRotations == 8)
		tempB = 0;
	else {
		tempB >>= numRotations;
		tempB <<= numRotations;
	}

	return  tempA | tempB;
}
