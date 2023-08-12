package solver;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class Main {
    public static final ScheduledExecutorService SCHEDULED = Executors.newScheduledThreadPool(1);
    public static final AtomicLong COUNTER = new AtomicLong(0);
    public static final List<Solver> SOLVERS = new ArrayList<>();
    public static final long MIN_IP_ADDRESS = 0x00000000L;
    public static final long MAX_IP_ADDRESS = 0xFFFFFFFFL;
    public static final byte DOT = '.';
    public static final byte[][] ARRAY;
    public static final Instant NOW;

    static {
        ARRAY = new byte[256][];
        for (int i = 0; i < 256; i++) {
            ARRAY[i] = Integer.toString(i).getBytes(StandardCharsets.US_ASCII);
        }
        NOW = Instant.now();
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("You must provide a SHA-256 hash (hex format)!");
            System.exit(-1);
            return;
        }

        byte[] bytes = HexFormat.of().parseHex(args[0]);
        int threads = Integer.getInteger("threads", Runtime.getRuntime().availableProcessors());
        boolean useIntrinsics = !Boolean.getBoolean("noIntrinsics");
        System.out.println("Searching for: " + args[0]);
        System.out.println(" * Threads: " + threads);

        long total = MAX_IP_ADDRESS - MIN_IP_ADDRESS + 2;
        long ip = MIN_IP_ADDRESS;
        long step = total / threads;

        int[] hashState = SHA2.toState(bytes);
        for (int i = 0; i < threads; i++) {
            long start = ip;
            long end = ip + step;

            Solver solver = new Solver(hashState, start, end, useIntrinsics);
            SOLVERS.add(solver);
            Thread t = new Thread(solver);
            t.setPriority(Thread.NORM_PRIORITY);
            t.start();
            ip += step;
        }

        SCHEDULED.scheduleAtFixedRate(Main::printProgressBar, 5, 5, TimeUnit.SECONDS);
    }


    public static void printProgressBar() {
        for (Solver solver : SOLVERS) {
            solver.report();
        }

        double elapsedSecs = Duration.between(NOW, Instant.now()).toMillis() / 1000D;
        long processed = COUNTER.get();
        long ipsRemaining = MAX_IP_ADDRESS - processed;
        double ipsPerSec = processed / elapsedSecs;
        double progress = ((double) processed / MAX_IP_ADDRESS) * 100D;
        double estimatedTimeRemaining = ipsRemaining / ipsPerSec;

        System.out.printf("%d/%d IPs | %.2f IPs/sec | Progress: %.2f%% | ETA: %.2fs | Elapsed: %.2fs%n", processed, MAX_IP_ADDRESS, ipsPerSec, progress, estimatedTimeRemaining, elapsedSecs);
    }

    public static class Solver implements Runnable {
        private final long start;
        private final long end;
        private final int[] hash;
        private final boolean useIntrinsics;
        private long lastReport;
        private long progress;

        private final byte[] b7 = SHA2.buffer(7);
        private final byte[] b8 = SHA2.buffer(8);
        private final byte[] b9 = SHA2.buffer(9);
        private final byte[] b10 = SHA2.buffer(10);
        private final byte[] b11 = SHA2.buffer(11);
        private final byte[] b12 = SHA2.buffer(12);
        private final byte[] b13 = SHA2.buffer(13);
        private final byte[] b14 = SHA2.buffer(14);
        private final byte[] b15 = SHA2.buffer(15);

        public Solver(int[] hash, long start, long end, boolean useIntrinsics) {
            this.hash = hash;
            this.start = start;
            this.end = end;
            this.useIntrinsics = useIntrinsics;
            this.lastReport = 0;
            this.progress = 0;
        }

        private byte[] buf(int size) {
            return switch (size) {
                case 7 -> b7;
                case 8 -> b8;
                case 9 -> b9;
                case 10 -> b10;
                case 11 -> b11;
                case 12 -> b12;
                case 13 -> b13;
                case 14 -> b14;
                case 15 -> b15;
                default -> null;
            };
        }

        @Override
        public void run() {
            SHA2 sha2;
            if (useIntrinsics) {
                sha2 = new SHA2WithIntrinsics();
            } else {
                sha2 = new SHA2NoIntrinsics();
            }
            int[] out = sha2.state;
            int[] hash = this.hash;
            long start = this.start;
            long end = this.end;
            byte[][] ARRAY = Main.ARRAY;
            int count = (int) (end - start);
            while (count-- != 0) {
                process(sha2, out, hash, start, ARRAY, count);
                this.progress++;
            }
        }

        private void process(SHA2 sha2, int[] out, int[] hash, long start, byte[][] ARRAY, int count) {
            long addr = start + count;
            byte[] a1, a2, a3, a4;
            {
                int n1 = ((byte) (addr >> 24)) & 0xFF;
                int n2 = ((byte) (addr >> 16)) & 0xFF;
                int n3 = ((byte) (addr >> 8)) & 0xFF;
                int n4 = ((byte) addr) & 0xFF;
                a1 = ARRAY[n1];
                a2 = ARRAY[n2];
                a3 = ARRAY[n3];
                a4 = ARRAY[n4];
            }

            int i = 0;
            int size = 3 + a1.length + a2.length + a3.length + a4.length;

            byte[] address = buf(size);

            i = putOctet(address, i, a1);
            address[i++] = DOT;
            i = putOctet(address, i, a2);
            address[i++] = DOT;
            i = putOctet(address, i, a3);
            address[i++] = DOT;
            putOctet(address, i, a4);

            sha2.digest(address, size);
            for (int j = 0; j < 8; j++) {
                if (hash[j] != out[j]) {
                    return;
                }
            }
            System.out.println("Found!: " + new String(address, 0, size));
            printProgressBar();
            System.exit(0);
        }

        private static int putOctet(byte[] address, int i, byte[] a) {
            int len = a.length;
            switch (len) {
                case 3:
                    address[i + 2] = a[2];
                case 2:
                    address[i + 1] = a[1];
                default:
                    address[i] = a[0];
            }
            return i + len;
        }

        public void report() {
            long delta = this.progress - this.lastReport;
            COUNTER.addAndGet(delta);
            this.lastReport = this.progress;
        }
    }
}
