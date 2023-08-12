package solver;

abstract class SHA2 {
    protected final int[] state = new int[8];
    protected final int[] W = new int[64];

    static byte[] buffer(int len) {
        byte[] buf = new byte[64];
        buf[len] = (byte) 0x80;
        return buf;
    }

    static int[] toState(byte[] hash) {
        if (hash.length != 32) {
            throw new IllegalArgumentException("Bad hash length for sha256");
        }
        int[] state = new int[8];
        state[0] = fromBytes(hash, 0);
        state[1] = fromBytes(hash, 4);
        state[2] = fromBytes(hash, 8);
        state[3] = fromBytes(hash, 12);
        state[4] = fromBytes(hash, 16);
        state[5] = fromBytes(hash, 20);
        state[6] = fromBytes(hash, 24);
        state[7] = fromBytes(hash, 28);
        return state;
    }

    public final void digest(byte[] in, int inLen) {
        int[] state = this.state;
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        // int bitsProcessed = inLen << 3;
        // SHA2.i2bBig4(bitsProcessed, in, 60);
        // bitsProcessed for ipv4 address would be always
        // less than 255 bits. (15 << 3) == 120
        in[63] = (byte) (inLen << 3);
        implCompress0(W, state, in);
    }

    abstract void implCompress0(int[] W, int[] state, byte[] buf);

    private static int fromBytes(byte[] b, int off) {
        return b[off] << 24 | (b[off + 1] & 0xff) << 16 | (b[off + 2] & 0xff) << 8 | (b[off + 3] & 0xff);
    }
}
