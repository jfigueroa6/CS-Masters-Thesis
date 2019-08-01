#pragma once
#ifndef LEA_H
#define LEA_H
#define LEA_BLOCK_SIZE	128
#define WORD_SIZE	32
#define KEY_128		128
#define KEY_192		192
#define KEY_256		256
#define ROUNDS_128	24
#define ROUNDS_192	28
#define ROUNDS_256	32
#include <vector>
#include <array>

class LEA {
public:
	// Functions
	uint8_t* encryption_128(const uint8_t * plaintext, const uint8_t* master_key, const bool generate_keys = true);
	uint8_t* encryption_192(const uint8_t * plaintext, const uint8_t* master_key, const bool generate_keys = true);
	uint8_t* encryption_256(const uint8_t * plaintext, const uint8_t* master_key, const bool generate_keys = true);
	uint8_t* decryption_128(const uint8_t* ciphertext, const uint8_t* master_key, const bool generate_keys = true);
	uint8_t* decryption_192(const uint8_t* ciphertext, const uint8_t* master_key, const bool generate_keys = true);
	uint8_t* decryption_256(const uint8_t* ciphertext, const uint8_t* master_key, const bool generate_keys = true);

private:
	// Private Helper Functions
	void generate_round_keys(const std::vector<uint32_t>& master_key, const int num_rounds);
	uint32_t rotate_left(const uint32_t word, const uint32_t num_bits);
	uint32_t rotate_right(const uint32_t word, const uint32_t num_bits);
	uint8_t* encryption_process(const uint8_t* plaintext, const int num_rounds);
	uint8_t* decryption_process(const uint8_t* ciphertext, const int num_rounds);
	
	// Private Variables
	std::vector<std::vector<uint32_t>> round_keys;
	
	// LEA constants
	const std::array<uint32_t, 8> lea_constants = {
		3287280091ul, 1147300610ul, 2044886154ul, 2027892972ul,
		1902027934ul, 3347438090ul, 3763270186ul, 3854829911ul
	};

};

#endif // !LEA_H

