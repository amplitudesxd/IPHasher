/*
    SHA256 OpenCL Optimized kernel
    (c) B. Kerler 2018
    MIT License

	Modified from: https://github.com/bkerler/MR/blob/master/MobileRevelator/python/Library/sha256.cl
*/

#define F1(x,y,z)   (bitselect(z,y,x))
#define F0(x,y,z)   (bitselect (x, y, (x ^ z)))
#define mod(x,y) (x % y)
#define shr32(x,n) ((x) >> (n))
#define rotl32(a,n) rotate ((a), (n))

unsigned int SWAP (unsigned int val) {
    return (rotate(((val) & 0x00FF00FF), 24U) | rotate(((val) & 0xFF00FF00), 8U));
}

#define S0(x) (rotl32 ((x), 25u) ^ rotl32 ((x), 14u) ^ shr32 ((x),  3u))
#define S1(x) (rotl32 ((x), 15u) ^ rotl32 ((x), 13u) ^ shr32 ((x), 10u))
#define S2(x) (rotl32 ((x), 30u) ^ rotl32 ((x), 19u) ^ rotl32 ((x), 10u))
#define S3(x) (rotl32 ((x), 26u) ^ rotl32 ((x), 21u) ^ rotl32 ((x),  7u))

#define SHA256C00 0x428a2f98u
#define SHA256C01 0x71374491u
#define SHA256C02 0xb5c0fbcfu
#define SHA256C03 0xe9b5dba5u
#define SHA256C04 0x3956c25bu
#define SHA256C05 0x59f111f1u
#define SHA256C06 0x923f82a4u
#define SHA256C07 0xab1c5ed5u
#define SHA256C08 0xd807aa98u
#define SHA256C09 0x12835b01u
#define SHA256C0a 0x243185beu
#define SHA256C0b 0x550c7dc3u
#define SHA256C0c 0x72be5d74u
#define SHA256C0d 0x80deb1feu
#define SHA256C0e 0x9bdc06a7u
#define SHA256C0f 0xc19bf174u
#define SHA256C10 0xe49b69c1u
#define SHA256C11 0xefbe4786u
#define SHA256C12 0x0fc19dc6u
#define SHA256C13 0x240ca1ccu
#define SHA256C14 0x2de92c6fu
#define SHA256C15 0x4a7484aau
#define SHA256C16 0x5cb0a9dcu
#define SHA256C17 0x76f988dau
#define SHA256C18 0x983e5152u
#define SHA256C19 0xa831c66du
#define SHA256C1a 0xb00327c8u
#define SHA256C1b 0xbf597fc7u
#define SHA256C1c 0xc6e00bf3u
#define SHA256C1d 0xd5a79147u
#define SHA256C1e 0x06ca6351u
#define SHA256C1f 0x14292967u
#define SHA256C20 0x27b70a85u
#define SHA256C21 0x2e1b2138u
#define SHA256C22 0x4d2c6dfcu
#define SHA256C23 0x53380d13u
#define SHA256C24 0x650a7354u
#define SHA256C25 0x766a0abbu
#define SHA256C26 0x81c2c92eu
#define SHA256C27 0x92722c85u
#define SHA256C28 0xa2bfe8a1u
#define SHA256C29 0xa81a664bu
#define SHA256C2a 0xc24b8b70u
#define SHA256C2b 0xc76c51a3u
#define SHA256C2c 0xd192e819u
#define SHA256C2d 0xd6990624u
#define SHA256C2e 0xf40e3585u
#define SHA256C2f 0x106aa070u
#define SHA256C30 0x19a4c116u
#define SHA256C31 0x1e376c08u
#define SHA256C32 0x2748774cu
#define SHA256C33 0x34b0bcb5u
#define SHA256C34 0x391c0cb3u
#define SHA256C35 0x4ed8aa4au
#define SHA256C36 0x5b9cca4fu
#define SHA256C37 0x682e6ff3u
#define SHA256C38 0x748f82eeu
#define SHA256C39 0x78a5636fu
#define SHA256C3a 0x84c87814u
#define SHA256C3b 0x8cc70208u
#define SHA256C3c 0x90befffau
#define SHA256C3d 0xa4506cebu
#define SHA256C3e 0xbef9a3f7u
#define SHA256C3f 0xc67178f2u 

__constant uint k_sha256[64] = {
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

#define SHA256_STEP(F0a,F1a,a,b,c,d,e,f,g,h,x,K) 	\
{                                                	\
  h += K;                                        	\
  h += x;                                        	\
  h += S3 (e);                           			\
  h += F1a (e,f,g);                              	\
  d += h;                                       	\
  h += S2 (a);                           			\
  h += F0a (a,b,c);                              	\
}

#define SHA256_EXPAND(x,y,z,w) (S1 (x) + y + S0 (z) + w) 

static void sha256_process(const unsigned int *W, unsigned int *digest) {
	unsigned int A = 0x6A09E667;
	unsigned int B = 0xBB67AE85;
	unsigned int C = 0x3C6EF372;
	unsigned int D = 0xA54FF53A;
	unsigned int E = 0x510E527F;
	unsigned int F = 0x9B05688C;
	unsigned int G = 0x1F83D9AB;
	unsigned int H = 0x5BE0CD19;
	
	unsigned int a = A;
	unsigned int b = B;
	unsigned int c = C;
	unsigned int d = D;
	unsigned int e = E;
	unsigned int f = F;
	unsigned int g = G;
	unsigned int h = H;

	unsigned int w0_t = W[0];
	unsigned int w1_t = W[1];
	unsigned int w2_t = W[2];
	unsigned int w3_t = W[3];
	unsigned int w4_t = W[4];
	unsigned int w5_t = W[5];
	unsigned int w6_t = W[6];
	unsigned int w7_t = W[7];
	unsigned int w8_t = W[8];
	unsigned int w9_t = W[9];
	unsigned int wa_t = W[10];
	unsigned int wb_t = W[11];
	unsigned int wc_t = W[12];
	unsigned int wd_t = W[13];
	unsigned int we_t = W[14];
	unsigned int wf_t = W[15];

	#define ROUND_EXPAND(i)                           \
	{                                                 \
		w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t);  \
		w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
		w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
		w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
		w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
		w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t);  \
		w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
		w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
		w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
		w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
		wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
		wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
		wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
		wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t);  \
		we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t);  \
		wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
	}

	#define ROUND_STEP(i)                                                   \
	{                                                                       \
		SHA256_STEP (F0, F1, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
		SHA256_STEP (F0, F1, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
		SHA256_STEP (F0, F1, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
		SHA256_STEP (F0, F1, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
		SHA256_STEP (F0, F1, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
		SHA256_STEP (F0, F1, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
		SHA256_STEP (F0, F1, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
		SHA256_STEP (F0, F1, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
		SHA256_STEP (F0, F1, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
		SHA256_STEP (F0, F1, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
		SHA256_STEP (F0, F1, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
		SHA256_STEP (F0, F1, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
		SHA256_STEP (F0, F1, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
		SHA256_STEP (F0, F1, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
		SHA256_STEP (F0, F1, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
		SHA256_STEP (F0, F1, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
	}

	ROUND_STEP (0);

	ROUND_EXPAND();
	ROUND_STEP(16);

	ROUND_EXPAND();
	ROUND_STEP(32);

	ROUND_EXPAND();
	ROUND_STEP(48);

	digest[0] = A + a;
	digest[1] = B + b;
	digest[2] = C + c;
	digest[3] = D + d;
	digest[4] = E + e;
	digest[5] = F + f;
	digest[6] = G + g;
	digest[7] = H + h;
}

static unsigned int uint8_to_uint32(unsigned char *bytes) {
    return (unsigned int) bytes[0] << 24 |
           (unsigned int) bytes[1] << 16 |
           (unsigned int) bytes[2] << 8  |
           (unsigned int) bytes[3];
}

static bool matches(const unsigned int* p1, __constant const unsigned int* p2) {
    if (p1[0] != p2[0]) {
        return false;
    }
    if (p1[1] != p2[1]) {
        return false;
    }
    return true;
}

static void copy(char* dst, const char* src, size_t n) {
    while (n && (*dst++ = *src++)) {
        n--;
    }
}

__kernel void sha256_range(
	__constant const char* TABLE,
    __constant const unsigned int* TARGET,
    __global char* result_data,
    __global uint* completed,
    __global uint* progress,
    ulong start,
    ulong end) {

	if (atomic_add(completed, 0) == 1)
		return;

	ulong gid = get_global_id(0);
	ulong total_work_items = get_global_size(0);

	ulong total_range = end - start;
	ulong range_per_item = total_range / total_work_items;

	ulong worker_start = start + gid * range_per_item;
	ulong worker_end = (gid == total_work_items - 1) ? end : worker_start + range_per_item;

	unsigned char data[64];
	unsigned int W[16];
	unsigned int state[8];
	int nums[4];
	
	for (ulong address = worker_start; address <= worker_end; address++) {
		if (address % 10000000 == 0) {
			atomic_add(progress, 10000000);
		}

		nums[0] = (unsigned char) (address >> 24);
		nums[1] = (unsigned char) (address >> 16);
		nums[2] = (unsigned char) (address >> 8);
		nums[3] = (unsigned char) address;

		int idx = 0;
		
		__constant const char* d = &TABLE[nums[0] * 3];
		if (d[2]) {
			data[idx++] = d[0];
			data[idx++] = d[1];
			data[idx++] = d[2];
		} else if (d[1]) {
			data[idx++] = d[0];
			data[idx++] = d[1];
		} else {
			data[idx++] = d[0];
		}

		data[idx++] = '.';
		d = &TABLE[nums[1] * 3];

		if (d[2]) {
			data[idx++] = d[0];
			data[idx++] = d[1];
			data[idx++] = d[2];
		} else if (d[1]) {
			data[idx++] = d[0];
			data[idx++] = d[1];
		} else {
			data[idx++] = d[0];
		}

		data[idx++] = '.';
		d = &TABLE[nums[2] * 3];

		if (d[2]) {
			data[idx++] = d[0];
			data[idx++] = d[1];
			data[idx++] = d[2];
		} else if (d[1]) {
			data[idx++] = d[0];
			data[idx++] = d[1];
		} else {
			data[idx++] = d[0];
		}

		data[idx++] = '.';
		d = &TABLE[nums[3] * 3];

		if (d[2]) {
			data[idx++] = d[0];
			data[idx++] = d[1];
			data[idx++] = d[2];
		} else if (d[1]) {
			data[idx++] = d[0];
			data[idx++] = d[1];
		} else {
			data[idx++] = d[0];
		}

		data[idx] = 0x80;

		for (int i = idx + 1; i < 56; i++) {
			data[i] = '\0';
		}

		ulong bit_len = idx * 8;
		for (int i = 0; i < 8; i++) {
			data[63 - i] = (unsigned char) (bit_len & 0xFF);
			bit_len >>= 8;
		}

		for (int i = 0; i < 16; i++) {
			W[i] = uint8_to_uint32(&data[i * 4]);
		}

		sha256_process(W, state);
		
		if (matches(state, TARGET)) {
			atomic_xchg(completed, 1);
			copy(result_data, (const char*)data, idx);
			return;
		}
	}
}