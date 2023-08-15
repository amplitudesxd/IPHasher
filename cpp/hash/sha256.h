#pragma once

#include <cstdint>

extern "C" {

	void sha256_process_arm(uint32_t state[8], const uint8_t data[], uint32_t length);

	// this function now assumes only one SHA256 block worth of data is supplied (must be 64 bytes long)
	void sha256_process_x86(uint32_t state[8], const uint8_t data[]/*, uint32_t length*/);

	void sha256_final_x86(uint32_t *state, unsigned char *digest);

}