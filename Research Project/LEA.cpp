#include <cstring>
#include "LEA.h"
/*
*	Performs encryption using a 128-bit key.
*/
uint8_t* LEA::encryption_128(const uint8_t* plaintext, const uint8_t* master_key, const bool generate_keys) {
	// Generate the keys if true, else use the existing keys
	if (generate_keys) {
		// Convert the key into 4 32-bit blocks
		std::vector<uint32_t> converted_master_key = { 0,0,0,0 };
		for (int i = 0, j = 0; i < 4; i++, j += 4) {
			std::memcpy(&converted_master_key[i], &master_key[j], 4);
		}
		generate_round_keys(converted_master_key, ROUNDS_128);
	}

	return encryption_process(plaintext, ROUNDS_128);
}

/*
*	Performs encryption using a 192-bit key.
*/
uint8_t* LEA::encryption_192(const uint8_t* plaintext, const uint8_t* master_key, const bool generate_keys) {
	// Generate the keys if true, else use the existing keys
	if (generate_keys) {
		// Convert the key into 6 32-bit blocks
		std::vector<uint32_t> converted_master_key = { 0,0,0,0 };
		for (int i = 0, j = 0; i < 6; i++, j += 4) {
			std::memcpy(&converted_master_key[i], &master_key[j], 4);
		}
		generate_round_keys(converted_master_key, ROUNDS_192);
	}

	return encryption_process(plaintext, ROUNDS_192);
}

/*
*	Performs encryption using a 256-bit key.
*/
uint8_t* LEA::encryption_256(const uint8_t* plaintext, const uint8_t* master_key, const bool generate_keys) {
	// Generate the keys if true, else use the existing keys
	if (generate_keys) {
		// Convert the key into 8 32-bit blocks
		std::vector<uint32_t> converted_master_key = { 0,0,0,0 };
		for (int i = 0, j = 0; i < 8; i++, j += 4) {
			std::memcpy(&converted_master_key[i], &master_key[j], 4);
		}
		generate_round_keys(converted_master_key, ROUNDS_256);
	}

	return encryption_process(plaintext, ROUNDS_256);
}

/*
*	Performs decryption using a 128-bit key.
*/
uint8_t* LEA::decryption_128(const uint8_t* ciphertext, const uint8_t* master_key, const bool generate_keys) {
	// Generate the keys if true, else use the existing keys
	if (generate_keys) {
		// Convert the key into 4 32-bit blocks
		std::vector<uint32_t> converted_master_key = { 0,0,0,0 };
		for (int i = 0, j = 0; i < 4; i++, j += 4) {
			std::memcpy(&converted_master_key[i], &master_key[j], 4);
		}
		generate_round_keys(converted_master_key, ROUNDS_128);
	}

	return decryption_process(ciphertext, ROUNDS_128);
}

/*
*	Performs decryption using a 192-bit key.
*/
uint8_t* LEA::decryption_192(const uint8_t* ciphertext, const uint8_t* master_key, const bool generate_keys) {
	// Generate the keys if true, else use the existing keys
	if (generate_keys) {
		// Convert the key into 6 32-bit blocks
		std::vector<uint32_t> converted_master_key = { 0,0,0,0 };
		for (int i = 0, j = 0; i < 6; i++, j += 4) {
			std::memcpy(&converted_master_key[i], &master_key[j], 4);
		}
		generate_round_keys(converted_master_key, ROUNDS_192);
	}

	return decryption_process(ciphertext, ROUNDS_192);
}

/*
*	Performs decryption using a 256-bit key.
*/
uint8_t* LEA::decryption_256(const uint8_t* ciphertext, const uint8_t* master_key, const bool generate_keys) {
	// Generate the keys if true, else use the existing keys
	if (generate_keys) {
		// Convert the key into 8 32-bit blocks
		std::vector<uint32_t> converted_master_key = { 0,0,0,0 };
		for (int i = 0, j = 0; i < 8; i++, j += 4) {
			std::memcpy(&converted_master_key[i], &master_key[j], 4);
		}
		generate_round_keys(converted_master_key, ROUNDS_256);
	}

	return decryption_process(ciphertext, ROUNDS_256);
}

/*
*	Generates the round keys. The key size determines how the round keys will be generated.
*/
void LEA::generate_round_keys(const std::vector<uint32_t>& master_key, const int num_rounds) {
	int rotation_steps[] = { 1, 3, 6, 11, 13, 17 },	// Used to determine the number of rotations for a key
		num_key_words = num_rounds == ROUNDS_128 ? 4 : 6; // If using 128 bit key, only deal with 4 words else dealing with 6
	std::vector<uint32_t> key_state(master_key);
	round_keys.resize(num_rounds);
	bool key_256 = num_rounds == ROUNDS_256 ? true : false; // Used to change the key state calculation since 256 bits uses a different approach

	// Generate the round keys
	for (int i = 0; i < num_rounds; i++) {
		int index_256 = 6 * i;	// Used by 256 bit key generation so it isn't calculated more than once
		// Create the round key words
		for (int j = 0; j < num_key_words; j++) {
			// A 256-bit key will follow a different approach
			if (!key_256) {
				uint32_t constant_temp = lea_constants[i % num_key_words];
				constant_temp = rotate_left(constant_temp, i + j);
				key_state[j] += constant_temp;
				key_state[j] = rotate_left(key_state[j], rotation_steps[j]);
			}
			else {
				uint32_t constant_temp = lea_constants[i % 8];
				constant_temp = rotate_left(constant_temp, i + j);
				int key_state_index = (index_256 + j) % 8;
				key_state[key_state_index] += constant_temp;
				key_state[key_state_index] = rotate_left(key_state[key_state_index], rotation_steps[j]);
			}
		}

		// Save the round key
		if (num_rounds == ROUNDS_128)
			round_keys[i] = { key_state[0], key_state[1], key_state[2], key_state[1], key_state[3], key_state[1] };
		else if (num_rounds == ROUNDS_192)
			round_keys[i] = { key_state[0], key_state[1], key_state[2], key_state[3], key_state[4], key_state[5] };
		else {
			round_keys[i] = { key_state[index_256 % 8], key_state[(index_256 + 1) % 8], key_state[(index_256 + 2) % 8],
				key_state[(index_256 + 3) % 8], key_state[(index_256 + 4) % 8], key_state[(index_256 + 5) % 8]
			};
		}
	}

}


/*
*	Performs a left rotation the given number of bits.
*/
uint32_t LEA::rotate_left(uint32_t word, const uint32_t num_bits) {
	return (word << num_bits) | (word >> (WORD_SIZE - num_bits));
}

/*
*	Performs a right rotation the given number of bits.
*/
uint32_t LEA::rotate_right(uint32_t word, const uint32_t num_bits) {
	return (word >> num_bits) | (word << (WORD_SIZE - num_bits));
}

/*
*	Performs the encryption rounds. The result is the ciphertext.
*/
uint8_t* LEA::encryption_process(const uint8_t* plaintext, const int num_rounds) {
	//Convert the plaintext into Word_Blocks
	std::array<uint32_t, 4> intermediate_state = std::array<uint32_t, 4>();
	for (int i = 0, j = 0; i < 4; i++, j += 4) {
		std::memcpy(&intermediate_state[i], &plaintext[j], 4);
	}

	//Perform the encryption rounds
	for (int i = 0; i < num_rounds; i++) {
		// Copy the intermediate_state words which will be used to store the modifications
		uint32_t x0 = intermediate_state[0],
			x1 = intermediate_state[1],
			x2 = intermediate_state[2],
			x3 = intermediate_state[3];

		// New x3 is just previous x0
		intermediate_state[3] = x0;

		// Generate new x2 from x3
		x3 ^= round_keys[i][5];
		x3 += x2 ^ round_keys[i][4];	// Modular addition between x3 and XOR result of x2 and round key subword 4
		x3 = rotate_right(x3, 3);
		intermediate_state[2] = x3;

		// Generate new x1 from x2
		x2 ^= round_keys[i][3];
		x2 += x1 ^ round_keys[i][2];	// Modular addition between x2 and XOR result of x1 and round key subword 2
		x2 = rotate_right(x2, 5);
		intermediate_state[1] = x2;

		// Generate new x0 from x1
		x1 ^= round_keys[i][1];
		x1 += x0 ^ round_keys[i][0];	// Modular addition between x1 and XOR result of x0 and round key subword 0
		x1 = rotate_left(x1, 9);
		intermediate_state[0] = x1;
	}

	// Convert the Word_Blocks back to one single 128-bit Bitset
	uint8_t* result = new uint8_t[16];
	for (int i = 0, j = 0; i < 4; i++, j += 4) {
		std::memcpy(&result[j], &intermediate_state[i], 4);
	}

	return result;
}

/*
*	Performs the decryption rounds. The result is the plaintext.
*/
uint8_t* LEA::decryption_process(const uint8_t* ciphertext, const int num_rounds) {
	//Convert the plaintext into Word_Blocks
	std::array<uint32_t, 4> intermediate_state = std::array<uint32_t, 4>();
	for (int i = 0, j = 0; i < 4; i++, j += 4) {
		std::memcpy(&intermediate_state[i], &ciphertext[j], 4);
	}

	//Perform the decryption rounds
	for (int i = num_rounds - 1; i >= 0; i--) {
		// Copy the intermediate_state words which will be used to store the modifications
		uint32_t x0 = intermediate_state[0],
			x1 = intermediate_state[1],
			x2 = intermediate_state[2],
			x3 = intermediate_state[3];

		// New x0 is just previous x3
		intermediate_state[0] = x3;

		// Generate new x1 from x0
		x0 = rotate_right(x0, 9);
		x0 -= x3 ^ round_keys[i][0];	// Modular subtraction between x0 and XOR result of x3 and round key subword 0
		x0 ^= round_keys[i][1];
		intermediate_state[1] = x0;

		// Generate new x2 from x1
		x1 = rotate_left(x1, 5);
		x1 -= x0 ^ round_keys[i][2]; // Modular subtraction between x1 and XOR result of x0 and round key subword 2
		x1 ^= round_keys[i][3];
		intermediate_state[2] = x1;

		// Generate new x3 from x2
		x2 = rotate_left(x2, 3);
		x2 -= x1 ^ round_keys[i][4];	// Modular subtraction between x2 and XOR result of x1 and round key subword 4
		x2 ^= round_keys[i][5];
		intermediate_state[3] = x2;
	}

	// Convert the Word_Blocks back to one single 128-bit Bitset
	uint8_t* result = new uint8_t[16];
	for (int i = 0, j = 0; i < 4; i++, j += 4) {
		std::memcpy(&result[j], &intermediate_state[i], 4);
	}

	return result;
}
