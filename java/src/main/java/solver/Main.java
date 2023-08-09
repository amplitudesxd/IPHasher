package solver;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class Main {
    public static final ScheduledExecutorService SCHEDULED = Executors.newScheduledThreadPool(1);
    public static final ExecutorService EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();
    public static final AtomicLong COUNTER = new AtomicLong(0);
    public static final List<Solver> SOLVERS = new ArrayList<>();
    public static final long MIN_IP_ADDRESS = 0x00000000L;
    public static final long MAX_IP_ADDRESS = 0xFFFFFFFFL;
    public static final byte DOT = '.';
    public static final byte[][] ARRAY;
    public static final Instant NOW;

    static {
        if (Boolean.getBoolean("enableACCP")) {
            AmazonCorrettoCryptoProvider.install();
            try {
                if (MessageDigest.getInstance("SHA-256").getProvider().getName().equals(AmazonCorrettoCryptoProvider.PROVIDER_NAME)) {
                    System.out.println("Successfully installed ACCP.");
                } else {
                    throw new RuntimeException(
                        "An error happened during the initialization of ACCP, falling back to the default provider",
                        AmazonCorrettoCryptoProvider.INSTANCE.getLoadingError()
                    );
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        } else {
            System.out.println("ACCP is disabled, using default provider");
        }

        ARRAY = new byte[256][];
        for (int i = 0; i < 256; i++) {
            ARRAY[i] = String.valueOf(i).getBytes(StandardCharsets.UTF_8);
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
        System.out.println("Searching for: " + args[0]);
        System.out.println(" * Threads: " + threads);

        long total = MAX_IP_ADDRESS - MIN_IP_ADDRESS + 2;
        long ip = MIN_IP_ADDRESS;
        long step = total / threads;

        for (int i = 0; i < threads; i++) {
            long start = ip;
            long end = ip + step;

            Solver solver = new Solver(bytes, start, end);
            SOLVERS.add(solver);
            EXECUTOR.execute(solver);
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
        private final MessageDigest digest;
        private final byte[] bytes;
        private byte[] address;
        private long lastReport;
        private long progress;

        public Solver(byte[] bytes, long start, long end) {
            this.bytes = bytes;
            this.start = start;
            this.end = end;
            this.address = new byte[4 + 3]; // 4 chars + 3 dots
            this.lastReport = 0;
            this.progress = 0;

            try {
                this.digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void run() {
            for (long addr = start; addr < end; addr++) {
                byte size = 3; // 3 dots

                int n1 = ((byte) (addr >> 24)) & 0xFF;
                int n2 = ((byte) (addr >> 16)) & 0xFF;
                int n3 = ((byte) (addr >> 8)) & 0xFF;
                int n4 = ((byte) addr) & 0xFF;

                byte n1s = 1;
                byte n2s = 1;
                byte n3s = 1;
                byte n4s = 1;

                if (n1 >= 100) n1s++;
                if (n1 >= 10) n1s++;

                if (n2 >= 100) n2s++;
                if (n2 >= 10) n2s++;

                if (n3 >= 100) n3s++;
                if (n3 >= 10) n3s++;

                if (n4 >= 100) n4s++;
                if (n4 >= 10) n4s++;

                size += n1s + n2s + n3s + n4s;
                if (size != this.address.length) {
                    this.address = new byte[size];
                }

                byte i = 0;

                byte[] a1 = ARRAY[n1];
                byte[] a2 = ARRAY[n2];
                byte[] a3 = ARRAY[n3];
                byte[] a4 = ARRAY[n4];

                System.arraycopy(a1, 0, this.address, i, n1s);
                i += n1s;
                this.address[i++] = DOT;

                System.arraycopy(a2, 0, this.address, i, n2s);
                i += n2s;
                this.address[i++] = DOT;

                System.arraycopy(a3, 0, this.address, i, n3s);
                i += n3s;
                this.address[i++] = DOT;

                System.arraycopy(a4, 0, this.address, i, n4s);

                if (Arrays.equals(this.bytes, this.digest.digest(this.address))) {
                    System.out.println("Found!: " + new String(this.address));
                    printProgressBar();
                    SCHEDULED.shutdown();
                    EXECUTOR.shutdown();
                    System.exit(0);
                    break;
                }

                this.progress++;
            }
        }

        public void report() {
            long delta = this.progress - this.lastReport;
            COUNTER.addAndGet(delta);
            this.lastReport = this.progress;
        }
    }
}