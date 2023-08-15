#pragma once

#include <cstdint>

#define DIGEST_LENGTH 32
#define MESSAGE_BLOCK_LENGTH 64

namespace hash {

	void sha256(const unsigned char *data, std::uint64_t len, unsigned char *digest);

}