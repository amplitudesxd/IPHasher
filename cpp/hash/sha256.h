#pragma once

extern "C" {

	void sha256_process_arm(uint32_t state[8], const uint8_t data[], uint32_t length);

	void sha256_process_x86(uint32_t state[8], const uint8_t data[], uint32_t length);

}