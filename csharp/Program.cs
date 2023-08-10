using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Timer = System.Timers.Timer;

class Program
{
    private const long min = 0x00000000L;
    private const long max = 0xFFFFFFFFL;
    private const long total = max - min + 2;
    private const byte dot = (byte) '.';
    private static readonly byte[][] lookup;
    private static readonly int threadCount = Environment.ProcessorCount;
    private static long globalProgress = 0;
    private static List<Thread> threads = new ();
    private static List<Solver> solvers = new();
    private static readonly Timer timer = new();
    private static readonly Stopwatch stopwatch = Stopwatch.StartNew();

    static Program()
    {
        lookup = new byte[256][];
        for (var i = 0; i < 256; i++)
            lookup[i] = Encoding.UTF8.GetBytes(i.ToString());

        timer.Interval = 5000;
        timer.Elapsed += (_, _) =>
        {
            solvers.ForEach(s => s.Report());
            var sec = stopwatch.ElapsedMilliseconds / 1000d;
            var processed = globalProgress;
            var remaining = max - processed;
            var ipps = processed / sec;
            var progress = ((double)processed / max) * 100d;
            var est = remaining / ipps;
            Console.WriteLine($"{processed:n}/{max:n} IPs | {ipps:n} IPs/sec | Progress: {progress:n}% | ETA: {est:n}s | Elapsed {sec:n}s");
        };
    }

    private static unsafe bool ArrayEquals(byte[] array1, byte[] array2)
    {
        fixed (byte* p1 = array1, p2 = array2)
            for (var i = 0; i < array1.Length; i++)
                if (p1[i] != p2[i])
                    return false;
        return true;
    }

    public static void Main(string[] args)
    {
        if (args.Length != 1) throw new Exception("You must provide a SHA-256 hash (hex format)!");
        Console.WriteLine("Looking for hash: {0}", args[0]);
        Console.WriteLine("Threads: {0}", threadCount);
        var bytes = Convert.FromHexString(args[0]);

        var ip = min;
        var step = total / threadCount;
        for (var i = 0; i < threadCount; i++)
        {
            var start = ip;
            var end = ip + step;

            var solver = new Solver(bytes, start, end);
            var thread = new Thread(solver.Run);
            threads.Add(thread);
            solvers.Add(solver);
            thread.Start();
            ip += step;
        }
        timer.Start();
    }

    private class Solver
    {
        private readonly long start;
        private readonly long end;
        private readonly HashAlgorithm hasher;
        private readonly byte[] search;
        private byte[] address = new byte[7];
        private byte[] hash = new byte[32];
        private long lastReport;
        private long progress;
        
        public Solver(byte[] search, long start, long end)
        {
            this.search = search;
            this.start = start;
            this.end = end;
            hasher = SHA256.Create();
            lastReport = 0;
            progress = 0;
        }
        
        public void Run()
        {
            for (var addr = start; addr < end; addr++)
            {
                var n1 = (addr >> 24) & 0xFF;
                var n2 = (addr >> 16) & 0xFF;
                var n3 = (addr >> 8) & 0xFF;
                var n4 = (addr) & 0xFF;
                int n1s, n2s, n3s, n4s;
                n1s = n2s = n3s = n4s = 1;
                if (n1 >= 100) n1s += 2;
                else if (n1 >= 10) n1s++;
                if (n2 >= 100) n2s += 2;
                else if (n2 >= 10) n2s++;
                if (n3 >= 100) n3s += 2;
                else if (n3 >= 10) n3s++;
                if (n4 >= 100) n4s += 2;
                else if (n4 >= 10) n4s++;

                var size = 3 + n1s + n2s + n3s + n4s;
                if (size != address.Length)
                    address = new byte[size];
                var i = 0;
                Buffer.BlockCopy(lookup[n1], 0, address, i, n1s);
                i += n1s;
                address[i++] = dot;
                Buffer.BlockCopy(lookup[n2], 0, address, i, n2s);
                i += n2s;
                address[i++] = dot;
                Buffer.BlockCopy(lookup[n3], 0, address, i, n3s);
                i += n3s;
                address[i++] = dot;
                Buffer.BlockCopy(lookup[n4], 0, address, i, n4s);

                hasher.TryComputeHash(address, hash, out _);
                if (ArrayEquals(search, hash))
                {
                    Console.WriteLine("Found: {0}", Encoding.UTF8.GetString(address));
                    threads.ForEach(t => t.Interrupt());
                    timer.Stop();
                    Environment.Exit(0);
                }
                progress++;
            }
        }

        public void Report()
        {
            Interlocked.Add(ref globalProgress, progress - lastReport);
            lastReport = progress;
        }
    }
}