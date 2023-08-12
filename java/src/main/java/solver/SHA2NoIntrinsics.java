package solver;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

final class SHA2NoIntrinsics extends SHA2 {
    private static final VarHandle INT_ARRAY = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.BIG_ENDIAN);
    private static final int[] ROUND_CONSTS = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    @Override
    void implCompress0(int[] W, int[] state, byte[] buf) {
        b2iBig64(buf, W);
        for (int t = 16; t < 64; t++) {
            int W_t2 = W[t - 2];
            int W_t15 = W[t - 15];

            int delta0_W_t15 =
                    ((W_t15 >>> 7) | (W_t15 << 25)) ^
                            ((W_t15 >>> 18) | (W_t15 << 14)) ^
                            (W_t15 >>> 3);

            int delta1_W_t2 =
                    ((W_t2 >>> 17) | (W_t2 << 15)) ^
                            ((W_t2 >>> 19) | (W_t2 << 13)) ^
                            (W_t2 >>> 10);

            W[t] = delta0_W_t15 + delta1_W_t2 + W[t - 7] + W[t - 16];
        }

        int a = state[0];
        int b = state[1];
        int c = state[2];
        int d = state[3];
        int e = state[4];
        int f = state[5];
        int g = state[6];
        int h = state[7];

        int[] ROUND_CONSTS = SHA2NoIntrinsics.ROUND_CONSTS;
        for (int i = 0; i < 64; i++) {
            int sigma0_a =
                    ((a >>> 2) | (a << 30)) ^
                            ((a >>> 13) | (a << 19)) ^
                            ((a >>> 22) | (a << 10));

            int sigma1_e =
                    ((e >>> 6) | (e << 26)) ^
                            ((e >>> 11) | (e << 21)) ^
                            ((e >>> 25) | (e << 7));

            int ch_efg = g ^ (e & (f ^ g));

            int maj_abc = (a & b) ^ ((a ^ b) & c);

            int T1 = h + sigma1_e + ch_efg + ROUND_CONSTS[i] + W[i];
            int T2 = sigma0_a + maj_abc;
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    private static void b2iBig64(byte[] in, int[] out) {
        out[0] = (int) INT_ARRAY.get(in, 0);
        out[1] = (int) INT_ARRAY.get(in, 4);
        out[2] = (int) INT_ARRAY.get(in, 8);
        out[3] = (int) INT_ARRAY.get(in, 12);
        out[4] = (int) INT_ARRAY.get(in, 16);
        out[5] = (int) INT_ARRAY.get(in, 20);
        out[6] = (int) INT_ARRAY.get(in, 24);
        out[7] = (int) INT_ARRAY.get(in, 28);
        out[8] = (int) INT_ARRAY.get(in, 32);
        out[9] = (int) INT_ARRAY.get(in, 36);
        out[10] = (int) INT_ARRAY.get(in, 40);
        out[11] = (int) INT_ARRAY.get(in, 44);
        out[12] = (int) INT_ARRAY.get(in, 48);
        out[13] = (int) INT_ARRAY.get(in, 52);
        out[14] = (int) INT_ARRAY.get(in, 56);
        out[15] = (int) INT_ARRAY.get(in, 60);
    }
}
