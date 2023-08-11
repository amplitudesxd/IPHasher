package solver;

final class SHA2NoIntrinsics extends SHA2 {

    void implDigest(int[] W, int[] state, byte[] in, int inLen, byte[] out) {
        int bitsProcessed = inLen << 3;

        SHA2.i2bBig4(0, in, 56);
        SHA2.i2bBig4(bitsProcessed, in, 60);
        implCompress0(W, state, in);

        SHA2.i2bBig(state, out);
    }

    private static void implCompress0(int[] W, int[] state, byte[] buf) {
        SHA2.b2iBig64(buf, W);
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

        int[] ROUND_CONSTS = SHA2.ROUND_CONSTS;
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
}
