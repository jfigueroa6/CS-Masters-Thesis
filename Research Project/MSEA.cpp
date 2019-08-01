#include <array>
#include <cstring>
#include "MSEA.h"

/*
*	Public function used to start the encryption process.
*/
uint8_t* MSEA::encryption(uint8_t* plaintext, CumulativeKey& key, const int numRounds, const bool generateKeys) {
	//Generate the round keys based on the given number of rounds, and if the generateKeys parameter is set
	if (generateKeys) {
		int swapKeySize = key.getSwapKeySize(),
			keyByteSize = key.getMasterKeySize() / 8;
		generateRoundKeys(key.getMasterKey(), keyByteSize, numRounds, swapKeySize);
	}

	//Perform message expansion
	int blockByteSize = key.getBlockSize() / 8,
		resultByteSize = key.getMasterKeySize() / 8;
	uint8_t* state = expandMessage(plaintext, blockByteSize, resultByteSize);

	// Perform encryption rounds
	int ddrBits = key.getSwapKeySize();
	for (int i = 0; i < numRounds; i++)
		encryptionRound(state, roundKeys[i], resultByteSize, ddrBits);

	// Two-phase swap
	uint16_t swapKey = key.getSwapKey();
	int stateBitSize = key.getMasterKeySize();
	twoPhaseSwap(state, swapKey, stateBitSize);

	return state;
}

/*
*	Public function used to start the decryption process.
*/
uint8_t* MSEA::decryption(uint8_t* ciphertext, CumulativeKey& key, const int numRounds, const bool generateKeys) {
	//Generate the round keys based on the given number of rounds, and if the generateKeys parameter is set
	if (generateKeys) {
		int swapKeySize = key.getSwapKeySize(),
			keyByteSize = key.getMasterKeySize() / 8;
		generateRoundKeys(key.getMasterKey(), keyByteSize, numRounds, swapKeySize);
	}

	int blockByteSize = key.getMasterKeySize() / 8,
		resultByteSize = key.getBlockSize() / 8;

	// Two-phase swap
	uint8_t* state = ciphertext;
	uint16_t swapKey = key.getSwapKey();
	int stateBitSize = key.getMasterKeySize();
	twoPhaseSwap(state, swapKey, stateBitSize);

	// Perform decryption rounds
	int ddrBits = key.getSwapKeySize();
	for (int i = numRounds - 1; i >= 0; i--)
		decryptionRound(state, roundKeys[i], blockByteSize, ddrBits);

	uint8_t* result = compressMessage(state, blockByteSize, resultByteSize);

	return result;
}

/*
*	Generates the round key based on the key, key size, number of rounds, and the DDR bits.
*/
void MSEA::generateRoundKeys(const uint8_t* masterKey, const int keyByteSize, const int numRounds, const int ddrBits) {
	// Copy the master key into an key sate to be used for round key generation
	uint8_t* keyState = new uint8_t[keyByteSize];
	std::memcpy(keyState, masterKey, keyByteSize);

	// Set round keys to the number of selected rounds
	roundKeys.resize(numRounds);

	for (int i = 0; i < numRounds; i++) {
		// Process from MSB to LSB a single byte at a time
		for (int i = 0; i < keyByteSize; i++) {
			// Performs 4-bit swap
			keyState[i] = roundKey4bitSwap(keyState[i]);
		}

		// Perform data dependent rotation
		keyDataDependentRotation(keyState, keyByteSize, ddrBits);
		uint8_t* roundKey = new uint8_t[keyByteSize];
		std::memcpy(roundKey, keyState, keyByteSize);
		roundKeys[i] = roundKey;
	}

	delete[] keyState;
}

/*
*	Performs the key 4-bit swap task. This is performed per byte.
*/
uint8_t MSEA::roundKey4bitSwap(uint8_t input) {
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
*	Performs Data Dependent Rotation on the key state. THis version is specific to the key generation.
*/
void MSEA::keyDataDependentRotation(uint8_t* keyState, const int keyByteSize, const int ddrBits) {
	const uint16_t rotationData[5] = { 0xFE00, 0xFF00, 0xFF80, 0xFFC0, 0xFFE0 },
		rotationDirectionLimiter[5] = { 0x0200, 0x0100, 0x0080, 0x0040, 0x0020 },
		rotationInfoLimiter[5] = { 0xFC00, 0xFE00, 0xFF00, 0xFF80, 0xFFC0 };
	// Get the rotation info.
	uint16_t ddrBytes, clearedDDRBytes;
	std::memcpy(&ddrBytes, &keyState[keyByteSize - 2], sizeof(uint16_t));
	clearedDDRBytes = ddrBytes & ~rotationData[ddrBits - 7];
	ddrBytes &= rotationData[ddrBits - 7];

	// Clear the DDR bits in the key state so they don't interfere.
	std::memcpy(&keyState[keyByteSize - 2], &clearedDDRBytes, sizeof(uint16_t));

	int rotationInfo = (ddrBytes & rotationInfoLimiter[ddrBits - 7]) >> (17 - ddrBits),
		rotationDirection = (ddrBytes & rotationDirectionLimiter[ddrBits - 7]) >> (16 - ddrBits);

	if (rotationDirection == 0)
		keyRotateRight(keyState, keyByteSize, rotationInfo, ddrBits, rotationData[ddrBits - 7]);
	else
		keyRotateLeft(keyState, keyByteSize, rotationInfo, ddrBits, rotationData[ddrBits - 7]);

	clearedDDRBytes = 0;
	std::memcpy(&clearedDDRBytes, &keyState[keyByteSize - 2], sizeof(uint16_t));
	clearedDDRBytes = (clearedDDRBytes & ~rotationData[ddrBits - 7]) | ddrBytes;
	std::memcpy(&keyState[keyByteSize - 2], &clearedDDRBytes, sizeof(uint16_t));
}

/*
*	Rotates the key state to left using the information in the DDR bits. 
*/
void MSEA::keyRotateLeft(uint8_t * data, const int keyByteSize, const int numRotations, const int ddrBits, const uint16_t limiter) {
	// Split key into 64-bit groups
	int numGroups,
		extraBytes = keyByteSize % sizeof(uint64_t);
	uint64_t* groups;

	// If the data block aligns to 64-bit blocks, no need for special processing, else process it differently.
	uint64_t rotationDataRemover;
	if (extraBytes == 0) {
		numGroups = keyByteSize / sizeof(uint64_t);
		rotationDataRemover = limiter;
		rotationDataRemover = ~(rotationDataRemover << 48);
		groups = new uint64_t[numGroups];
		for (int i = 0, j = 0; i < numGroups; i++, j += sizeof(uint64_t))
			std::memcpy(&groups[i], &data[j], sizeof(uint64_t));
	}
	else {
		numGroups = (keyByteSize / sizeof(uint64_t)) + 1;
		rotationDataRemover = keyLimiterAssistant(limiter, extraBytes);
		groups = new uint64_t[numGroups];
		for (int i = 0, j = 0; i < numGroups - 1; i++, j += sizeof(uint64_t))
			std::memcpy(&groups[i], &data[j], sizeof(uint64_t));
		groups[numGroups - 1] = 0;
		std::memcpy(&groups[numGroups - 1], &data[keyByteSize - extraBytes], extraBytes);
	}

	int numRotationsRemaining = numRotations,
		maxRotationsAllowed = extraBytes == 0 ? 64 - ddrBits : ((keyByteSize * 8) % 64) - ddrBits;

	while (numRotationsRemaining > 0) {
		// Process each 64 bit group. Only shift left max bits in maxRotations allowed since this is the
		// max amount allowed in the last group. The remaining 7 bits are the bits used for rotation information
		int roundNumRotations = numRotationsRemaining > maxRotationsAllowed ? maxRotationsAllowed : numRotationsRemaining;
		uint64_t carry = 0;

		for (int i = 0; i < numGroups; i++) {
			int maxSize = i == numGroups - 1 ? maxRotationsAllowed : 64;
			uint64_t tempCarry = (groups[i] >> (maxSize - roundNumRotations));
			groups[i] = (groups[i] << roundNumRotations) | carry;
			if (i == numGroups - 1)
				groups[i] &= rotationDataRemover;
			carry = tempCarry;
		}

		// Insert carry into the first group to complete the rotation
		groups[0] |= carry;

		numRotationsRemaining -= roundNumRotations;
	}

	
	if (extraBytes == 0) {
		for (int i = 0, j = 0; i < numGroups; i++, j += sizeof(uint64_t))
			std::memcpy(&data[j], &groups[i], sizeof(uint64_t));
	}
	else {
		for (int i = 0, j = 0; i < numGroups - 1; i++, j += sizeof(uint64_t))
			std::memcpy(&data[j], &groups[i], sizeof(uint64_t));
		std::memcpy(&data[keyByteSize - extraBytes], &groups[numGroups - 1], extraBytes);
	}

	delete[] groups;
}

/*
*	Rotates the key state to right using the information in the DDR bits.
*/
void MSEA::keyRotateRight(uint8_t * data, const int keyByteSize, const int numRotations, const int ddrBits, const uint16_t limiter) {
	// Split key into 64-bit groups
	int numGroups,
		extraBytes = keyByteSize % sizeof(uint64_t);
	uint64_t* groups;

	// If the data block aligns to 64-bit blocks, no need for special processing, else process it differently.
	uint64_t rotationDataRemover;
	if (extraBytes == 0) {
		numGroups = keyByteSize / sizeof(uint64_t);
		rotationDataRemover = limiter;
		rotationDataRemover = ~(rotationDataRemover << 48);
		groups = new uint64_t[numGroups];
		for (int i = 0, j = 0; i < numGroups; i++, j += sizeof(uint64_t))
			std::memcpy(&groups[i], &data[j], sizeof(uint64_t));
	}
	else {
		numGroups = (keyByteSize / sizeof(uint64_t)) + 1;
		rotationDataRemover = keyLimiterAssistant(limiter, extraBytes);
		groups = new uint64_t[numGroups];
		for (int i = 0, j = 0; i < numGroups - 1; i++, j += sizeof(uint64_t))
			std::memcpy(&groups[i], &data[j], sizeof(uint64_t));
		groups[numGroups - 1] = 0;
		std::memcpy(&groups[numGroups - 1], &data[keyByteSize - extraBytes], extraBytes);
	}

	int numRotationsRemaining = numRotations,
		maxRotationsAllowed = extraBytes == 0 ? 64 - ddrBits : ((keyByteSize * 8) % 64) - ddrBits;

	while (numRotationsRemaining > 0) {
		// Process each 64 bit group. Only shift right max bits in maxRotations allowed since this is the
		// max amount allowed in the last group. The remaining 7 bits are the bits used for rotation information
		int roundNumRotations = numRotationsRemaining > maxRotationsAllowed ? maxRotationsAllowed : numRotationsRemaining;
		uint64_t carry = 0;

		for (int i = numGroups - 1; i >= 0; i--) {
			int maxSize = i == numGroups - 1 ? maxRotationsAllowed : 64;
			uint64_t tempCarry = groups[i] << (64 - roundNumRotations);
			if (i == numGroups - 1)
				groups[i] &= rotationDataRemover;
			groups[i] = (groups[i] >> roundNumRotations) | carry;
			carry = tempCarry;
		}

		// Insert carry into the first group to complete the rotation
		groups[numGroups - 1] |= carry >> (64 - ddrBits);

		numRotationsRemaining -= roundNumRotations;
	}


	if (extraBytes == 0) {
		for (int i = 0, j = 0; i < numGroups; i++, j += sizeof(uint64_t))
			std::memcpy(&data[j], &groups[i], sizeof(uint64_t));
	}
	else {
		for (int i = 0, j = 0; i < numGroups - 1; i++, j += sizeof(uint64_t))
			std::memcpy(&data[j], &groups[i], sizeof(uint64_t));
		std::memcpy(&data[keyByteSize - extraBytes], &groups[numGroups - 1], extraBytes);
	}

	delete[] groups;
}

/*
*	Removes the data dependent rotation information from the key state, so it doesn't
*	interfere with the data portion.
*/
uint64_t MSEA::keyLimiterAssistant(uint16_t limiter, const int numExtraBytes) {
	int shiftBits = (numExtraBytes - sizeof(uint16_t)) * 8;
	uint64_t result = limiter;

	// Shift into proper position and negate to get the limiter for the rotation
	result = ~(result << shiftBits);
	// Shift to clear out the set bits to the left of the limiter since those will interfere. Using 48 to
	// account for the originial 16 bits of the limiter.
	result <<= (48 - shiftBits);
	result >>= (48 - shiftBits);

	return result;;
}

/*
*	Performs the expand message stage of the encryption process. This expands each byte into 2 bytes.
*/
uint8_t* MSEA::expandMessage(uint8_t* plaintext, const int blockByteSize, const int keyByteSize) {
	uint8_t* result = new uint8_t[keyByteSize];

	// Work on a byte which will be expaned to 2 bytes
	for (int i = 0, j = 0; i < blockByteSize; i++, j += 2) {
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
		std::memcpy(&result[j], &intermediate, sizeof(uint16_t));
	}

	return result;
}

/*
*	Performs the compress message stage of the decryption process. This reduces 2 bytes into
*	a byte.
*/
uint8_t* MSEA::compressMessage(uint8_t* state, const int blockByteSize, const int keyByteSize) {
	uint8_t* result = new uint8_t[blockByteSize];

	// Work on two bytes which will be compressed to 1 byte
	for (int i = 0, j = 0; i < blockByteSize; i++, j += 2) {
		// Copy two bytes into intermediate and One's complement
		uint16_t intermediate;
		std::memcpy(&intermediate, &state[j], sizeof(uint16_t));
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
		result[i] = (uint8_t)intermediate;
	}

	return result;
}

/*
*	Performs a DDR left rotation on 16-bit message. It is limited to the data portion of the
*	16-bits.
*/
uint16_t MSEA::messRotateLeft(uint16_t data, const int numRotations, const bool msb) {
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
uint16_t MSEA::messRotateRight(uint16_t data, const int numRotations, const bool msb) {
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
void MSEA::encryptionRound(uint8_t * state, uint8_t * key, const int stateByteSize, const int ddrBits) {
	// Divide state and key into 4 64-bit blocks
	std::array<uint8_t*, 4> blocks = std::array<uint8_t*, 4>(),
		keyBlocks = std::array<uint8_t*, 4>();
	bool unalignedBlocks = stateByteSize % 4 != 0;
	int subBlockByteSize = createSubBlocks(state, stateByteSize, blocks, unalignedBlocks);
	createSubBlocks(key, stateByteSize, keyBlocks, unalignedBlocks);

	// Perform modular addition
	modularAddition(blocks[3], blocks[2], subBlockByteSize);
	modularAddition(blocks[2], blocks[1], subBlockByteSize);
	modularAddition(blocks[1], blocks[0], subBlockByteSize);
	modularAddition(blocks[0], blocks[3], subBlockByteSize);

	// Perform Data Dependent Rotation
	roundDataDependentRotation(blocks, ddrBits, subBlockByteSize, unalignedBlocks);

	// Perform XOR on the 4 blocks and key blocks
	uint8_t* xorTemp = new uint8_t[subBlockByteSize];
	blockXOR(blocks[0], keyBlocks[0], subBlockByteSize);
	for (int i = 1; i < 4; i++) {
		std::memcpy(xorTemp, blocks[i - 1], subBlockByteSize);
		blockXOR(xorTemp, keyBlocks[i], subBlockByteSize);
		blockXOR(blocks[i], xorTemp, subBlockByteSize);
	}
	delete[] xorTemp;

	// Concatenate Groups
	std::array<uint8_t*, 2> mergedBlocks = std::array<uint8_t*, 2>();
	int mergedBlockByteSize = mergeBlocks(blocks, mergedBlocks, subBlockByteSize, unalignedBlocks);
	for (int i = 0; i < 4; i++) {
		delete[] blocks[i];
		delete[] keyBlocks[i];
	}

	// Perform final XOR and modular addition
	blockXOR(mergedBlocks[1], mergedBlocks[0], mergedBlockByteSize);
	modularAddition(mergedBlocks[0], mergedBlocks[1], mergedBlockByteSize);

	// Copy results back into state, and perform final cleanup
	std::memcpy(state, mergedBlocks[1], mergedBlockByteSize);
	std::memcpy(&state[mergedBlockByteSize], mergedBlocks[0], mergedBlockByteSize);
	delete[] mergedBlocks[0];
	delete[] mergedBlocks[1];
}

/*
*	Performs a single decryption round. The result is stored in the state.
*/
void MSEA::decryptionRound(uint8_t * state, uint8_t * key, const int stateByteSize, const int ddrBits) {
	// Perform modular subtraction and XOR. For modular subtraction, first half of state is block F, second half is block E
	modularSubtraction(&state[stateByteSize / 2], state, stateByteSize / 2);
	blockXOR(state, &state[stateByteSize / 2], stateByteSize / 2);

	// Divide state and key into 4 64-bit blocks
	std::array<uint8_t*, 4> blocks = std::array<uint8_t*, 4>(),
		keyBlocks = std::array<uint8_t*, 4>();
	bool unalignedBlocks = stateByteSize % 4 != 0;
	int subBlockByteSize = createSubBlocks(state, stateByteSize, blocks, unalignedBlocks);
	createSubBlocks(key, stateByteSize, keyBlocks, unalignedBlocks);

	// The blocks are in order 2, 3, 0, 1 so they must be reorder
	uint8_t* temp = blocks[0];
	blocks[0] = blocks[2];
	blocks[2] = temp;
	temp = blocks[1];
	blocks[1] = blocks[3];
	blocks[3] = temp;

	// Perform XOR on the 4 blocks and key blocks
	uint8_t* xorTemp = new uint8_t[subBlockByteSize];
	for (int i = 3; i > 0; i--) {
		std::memcpy(xorTemp, blocks[i - 1], subBlockByteSize);
		blockXOR(xorTemp, keyBlocks[i], subBlockByteSize);
		blockXOR(blocks[i], xorTemp, subBlockByteSize);
	}
	blockXOR(blocks[0], keyBlocks[0], subBlockByteSize);
	delete[] xorTemp;
	
	// Perform Data Dependent Rotation
	roundDataDependentRotation(blocks, ddrBits, subBlockByteSize, unalignedBlocks, true);

	// Perform modular addition
	modularSubtraction(blocks[0], blocks[3], subBlockByteSize);
	modularSubtraction(blocks[1], blocks[0], subBlockByteSize);
	modularSubtraction(blocks[2], blocks[1], subBlockByteSize);
	modularSubtraction(blocks[3], blocks[2], subBlockByteSize);

	// Copy result into state
	std::array<uint8_t*, 2> mergedBlocks = std::array<uint8_t*, 2>();
	int mergedBlockByteSize = mergeBlocks(blocks, mergedBlocks, subBlockByteSize, unalignedBlocks, false);
	std::memcpy(state, mergedBlocks[0], mergedBlockByteSize);
	std::memcpy(&state[mergedBlockByteSize], mergedBlocks[1], mergedBlockByteSize);
	
	// Cleanup
	for (int i = 0; i < 4; i++) {
		delete[] blocks[i];
		delete[] keyBlocks[i];
	}
	delete[] mergedBlocks[0];
	delete[] mergedBlocks[1];
}

/*
*	Creates 4 equal subblocks from the state. If the data size cannot be split equally, it will also align the data.
*/
int MSEA::createSubBlocks(uint8_t* data, const int dataByteSize, std::array<uint8_t*, 4>& blocks, const bool unalignedBlocks) {
	int blocksStep = dataByteSize / 4,
		subBlockByteSize = unalignedBlocks ? blocksStep + 1 : blocksStep;
	for (int i = 0, j = 0; i < 4; i++, j += blocksStep) {
		uint8_t* block = new uint8_t[subBlockByteSize];
		std::memcpy(block, &data[j], subBlockByteSize);

		// Unaligned blocks must be modified so that they can be processed in an aligned format.
		if (unalignedBlocks) {
			// Blocks 0 and 2 will have the last byte limited to the 4 most significant bits,
			// then it gets shifted to the right 4 bits so it can be easily added.
			if (i % 2 == 0) {
				block[subBlockByteSize - 1] &= 0xF0;
				block[subBlockByteSize - 1] >>= 4;
			}
			// Blocks 1 and 3 must be overall shifted left 4 bits except for the last byte which
			// only the 4 msbs are shifted.
			else {
				uint8_t carry = (block[subBlockByteSize - 1] & 0xF0) >> 4;
				block[subBlockByteSize - 1] &= 0x0F;
				for (int k = subBlockByteSize - 2; k >= 0; k--) {
					uint8_t tempCarry = (block[k] & 0xF0) >> 4;
					block[k] <<= 4;
					block[k] |= carry;
					carry = tempCarry;
				}
			}
		}

		blocks[i] = block;
	}

	return subBlockByteSize;
}

/*
*	Performs modular addition with response in the LHS parameter. Algorithm created using the following:
*	https://bisqwit.iki.fi/story/howto/bitmath/#UsingBitwiseOperationsWithXor
*/
void MSEA::modularAddition(uint8_t * lhs, uint8_t * rhs, const int blockByteSize) {
	int carry = 0;
	for (int i = 0; i < blockByteSize; i++) {
		uint8_t original = lhs[i];
		lhs[i] += rhs[i] + carry;
		// If the result in lhs[i] is less than the rhs operand, then that means the result overflowed, so set carry.
		carry = lhs[i] < original ? 1 : 0;
	}
}

/*
*	Performs modular subtraction with response in the LHS parameter. Algorithm created using the following:
*	https://bisqwit.iki.fi/story/howto/bitmath/#UsingBitwiseOperationsWithXor
*/
void MSEA::modularSubtraction(uint8_t * lhs, uint8_t * rhs, const int blockByteSize) {
	int carry = 0;
	for (int i = 0; i < blockByteSize; i++) {
		uint8_t original = lhs[i];
		lhs[i] -= rhs[i] + carry;
		// If the result in lhs[i] is greater than the original value, then the result underflowed, so set carry.
		carry = lhs[i] > original ? 1 : 0;
	}
}

/*
*	Performs XOR and stores the result in LHS.
*/
void MSEA::blockXOR(uint8_t * lhs, uint8_t * rhs, const int blockByteSize) {
	for (int i = 0; i < blockByteSize; i++)
		lhs[i] ^= rhs[i];
}

/*
*	Performs data dependent rotation on each of the subblocks. If it's for encryption, it reverses the direction.
*/
void MSEA::roundDataDependentRotation(std::array<uint8_t *, 4U> &blocks, const int ddrBits, const int subBlockByteSize, const bool unalignedBlocks, const bool reverse) {
	int maxRotationBits = unalignedBlocks ? 16 - ddrBits : 12 - ddrBits;
	for (unsigned int i = 0; i < blocks.size(); i++) {
		if (unalignedBlocks)
			blocks[i][subBlockByteSize - 1] &= 0x0F;

		uint16_t rotationData;
		std::memcpy(&rotationData, &blocks[i][subBlockByteSize - 2], sizeof(uint16_t));

		// Determine the rotation information
		int rotationDirection, rotationInfo, nonDDRBits, bytesToProcess;
		if (unalignedBlocks) {
			bytesToProcess = subBlockByteSize - 1;	// Since the last byte consist of all DDR bits, just ignore it in DDR
			nonDDRBits = 12 - ddrBits;
			rotationData >>= nonDDRBits;
			rotationDirection = rotationData & 1;
			rotationInfo = rotationData >> 1;
			rotationData <<= nonDDRBits;
		}
		else {
			rotationData >>= 16 - ddrBits;
			rotationDirection = rotationData & 1;
			rotationInfo = rotationData >> 1;
			rotationData <<= 16 - ddrBits;
			nonDDRBits = ddrBits > 8 ? 16 - ddrBits : 8 - ddrBits;	// 8 ddr bits or less is in last byte, all others in 2nd to last
			bytesToProcess = ddrBits >= 8 ? subBlockByteSize - 1 : subBlockByteSize;

		}

		// Perform the rotation. Reverse is used for decryption
		if (reverse) {
			if (rotationDirection == 0)
				roundRotateLeft(blocks[i], bytesToProcess, nonDDRBits, rotationInfo);
			else
				roundRotateRight(blocks[i], bytesToProcess, nonDDRBits, rotationInfo);
		}
		else {
			if (rotationDirection == 0)
				roundRotateRight(blocks[i], bytesToProcess, nonDDRBits, rotationInfo);
			else
				roundRotateLeft(blocks[i], bytesToProcess, nonDDRBits, rotationInfo);
		}

		// Restore rotation data back into the block
		uint16_t resultRotationData;
		std::memcpy(&resultRotationData, &blocks[i][subBlockByteSize - 2], sizeof(uint16_t));
		resultRotationData |= rotationData;
		std::memcpy(&blocks[i][subBlockByteSize - 2], &resultRotationData, sizeof(uint16_t));
	}
}

/*
*	Performs a left data dependent rotation on a subblock. 
*/
void MSEA::roundRotateLeft(uint8_t* data, const int bytesToProcess, const int nonDDRBitsInLastByte,const int numRotations) {
	const uint8_t ddrLimiter[8] = { 0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01 };
	data[bytesToProcess - 1] &= ddrLimiter[8 - nonDDRBitsInLastByte];

	int numRotationsRemaining = numRotations;
	while (numRotationsRemaining > 0) {
		// Process each byte. Only shift left max bits in nonDDRBitsInLastByte allowed since this is the
		// max amount allowed in the last byte.
		int roundNumRotations = numRotationsRemaining > nonDDRBitsInLastByte ? nonDDRBitsInLastByte : numRotationsRemaining;
		uint8_t carry = 0;
		

		for (int i = 0; i < bytesToProcess; i++) {
			int maxSize = i == bytesToProcess - 1 ? nonDDRBitsInLastByte : 8;
			uint8_t tempCarry = (data[i] >> (maxSize - roundNumRotations));
			data[i] = (data[i] << roundNumRotations) | carry;
			carry = tempCarry;
		}

		// Insert carry into the first group to complete the rotation
		data[0] |= carry;
		data[bytesToProcess - 1] &= ddrLimiter[8 - nonDDRBitsInLastByte];

		numRotationsRemaining -= roundNumRotations;
	}
}

/*
*	Performs a right data dependent rotation on a subblock.
*/
void MSEA::roundRotateRight(uint8_t * data, const int bytesToProcess, const int nonDDRBitsInLastByte, const int numRotations) {
	const uint8_t ddrLimiter[8] = { 0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01 };

	int numRotationsRemaining = numRotations;
	while (numRotationsRemaining > 0) {
		// Process each byte. Only shift left max bits in nonDDRBitsInLastByte allowed since this is the
		// max amount allowed in the last byte.
		int roundNumRotations = numRotationsRemaining > nonDDRBitsInLastByte ? nonDDRBitsInLastByte : numRotationsRemaining;
		uint8_t carry = 0;

		for (int i = bytesToProcess - 1; i >= 0; i--) {
			// For the last byte, get the carry into the correct position	
			uint8_t tempCarry = data[i] << (8 - roundNumRotations);
			if (i == bytesToProcess - 1)
				data[i] &= ddrLimiter[8 - nonDDRBitsInLastByte];
			data[i] = (data[i] >> roundNumRotations) | carry;
			carry = tempCarry;
		}

		// Insert carry into the first group to complete the rotation
		data[bytesToProcess - 1] |= carry >> (8 - nonDDRBitsInLastByte);

		numRotationsRemaining -= roundNumRotations;
	}
}

/*
*	Merges the 4 subblocks into 2 blocks, and returns the merged block size. Depending on the type of operation, the merge order is
*	changed.
*/
int MSEA::mergeBlocks(std::array<uint8_t*, 4> &blocks, std::array<uint8_t*, 2> &merged, const int subBlockByteSize, const bool unalignedBlocks, const bool encryption) {
	int mergedBlockByteSize = unalignedBlocks ? (subBlockByteSize - 1) * 2 : subBlockByteSize * 2;
	int blockOrder[4] = { 0, 1, 2, 3 };

	// If this is an encryption merge, chagne the order
	if (encryption) {
		blockOrder[0] = 2;
		blockOrder[1] = 0;
		blockOrder[2] = 3;
		blockOrder[3] = 1;
	}

	for (int i = 0, j = 0; i < 2; i++, j += 2) {
		uint8_t* temp = new uint8_t[mergedBlockByteSize];
		
		if (unalignedBlocks) {
			std::memcpy(temp, blocks[j], subBlockByteSize);

			// Shift each byte in the second block to the right 4 bits, so it can be merged. This does the opposite of
			// what is done to create the blocks in a previous function
			uint8_t carry = blocks[j + 1][0] << 4;
			temp[subBlockByteSize - 1] = (temp[subBlockByteSize - 1] << 4) | (blocks[j + 1][0] >> 4);
			// Stop at the second to last block since the last block must be handled differently
			for (int k = 1; k < subBlockByteSize - 1; k++) {
				uint8_t tempCarry = blocks[j + 1][k] << 4;
				temp[subBlockByteSize - 1 + k] = (blocks[j + 1][k] >> 4) | carry;
				carry = tempCarry;
			}
			temp[mergedBlockByteSize - 1] = blocks[j + 1][subBlockByteSize - 1] | carry;
		}
		else {
			std::memcpy(temp, blocks[j], subBlockByteSize);
			std::memcpy(&temp[subBlockByteSize], blocks[j + 1], subBlockByteSize);
		}

		merged[i] = temp;
	}

	return mergedBlockByteSize;
}

/*
*	Performs the two phase swap stage. 
*/
void MSEA::twoPhaseSwap(uint8_t* state, uint16_t swap, const int blockBitSize) {
	// Skip if swap is 0, or else it'll never do anything
	if (swap == 0)
		return;

	// Flip every ith bit determined by swap
	const uint8_t bitRetriever[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
	for (int i = swap - 1; i < blockBitSize; i += swap) {
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
	for (int i = 0; i < blockBitSize - (swap * 2); i += (swap * 2)) {
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
uint8_t MSEA::twoPhaseClearNonReleventBits(const uint8_t data, const int startBit, const int numBits) {
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
uint8_t MSEA::twoPhaseClearReleventBits(const uint8_t data, const int startBit, const int numBits) {
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
