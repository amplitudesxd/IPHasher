package solver;


import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

abstract class SHA2 {
    static final int[] ROUND_CONSTS = {
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
    private static final VarHandle INT_ARRAY
            = MethodHandles.byteArrayViewVarHandle(int[].class,
            ByteOrder.BIG_ENDIAN);

    static byte[] buffer(int len) {
        byte[] buf = new byte[64];
        buf[len] = (byte) 0x80;
        return buf;
    }

    protected final int[] state = new int[8];
    protected final int[] W = new int[64];

    public final void digest(byte[] in, int inLen, byte[] out) {
        int[] state = this.state;
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        implDigest(W, state, in, inLen, out);
    }

    abstract void implDigest(int[] W, int[] state, byte[] in, int inLen, byte[] out);

    static void b2iBig64(byte[] in, int[] out) {
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

    static void i2bBig(int[] in, byte[] out) {
        INT_ARRAY.set(out, 0, in[0]);
        INT_ARRAY.set(out, 4, in[1]);
        INT_ARRAY.set(out, 8, in[2]);
        INT_ARRAY.set(out, 12, in[3]);
        INT_ARRAY.set(out, 16, in[4]);
        INT_ARRAY.set(out, 20, in[5]);
        INT_ARRAY.set(out, 24, in[6]);
        INT_ARRAY.set(out, 28, in[7]);
    }

    static void i2bBig4(int val, byte[] out, int index) {
        INT_ARRAY.set(out, index, val);
    }
}
