#if defined(__ARM_ARCH_ISA_A64) && !defined(HASH_STD)

#include "hash.h"
#include "sha256.h"

namespace hash {

	void sha256(const unsigned char *data, std::uint64_t len, unsigned char *digest) {
		uint32_t state[8] = {
				0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
				0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
		};

		sha256_process_arm(state, data, len);

		for (int i = 0; i < 8; ++i) {
			digest[i * 4] = (state[i] >> 24) & 0xff;
			digest[i * 4 + 1] = (state[i] >> 16) & 0xff;
			digest[i * 4 + 2] = (state[i] >> 8) & 0xff;
			digest[i * 4 + 3] = state[i] & 0xff;
		}
	}

}

#endif