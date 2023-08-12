import hashlib
import multiprocessing
import time
import sys
import os

done = multiprocessing.Value('b', False)


class BarWriter:
    def __init__(self, total_ips):
        self.total_ips = total_ips
        self.processed_ips = multiprocessing.Value('i', 0)
        self.start_time = time.time()

    def update_progress_bar(self):
        processed_ips = self.processed_ips.value

        ips_per_sec = processed_ips / (time.time() - self.start_time)

        progress = (processed_ips / self.total_ips) * 100

        ips_remaining = self.total_ips - processed_ips
        estimated_time_remaining = 0 if ips_per_sec == 0 else ips_remaining / ips_per_sec

        print(f"{processed_ips}/{self.total_ips} IPs | {ips_per_sec:.2f} IPs/sec | Progress: {progress:.2f}% | ETA: {estimated_time_remaining:.2f} seconds | Elapsed: {time.time() - self.start_time:.2f} seconds", end='\r')


def progressBarUpdater(writer):
    while not done.value:
        writer.update_progress_bar()
        time.sleep(0.1)


def process_ips(start_ip, end_ip, target_hash, writer):
    global done

    h256 = hashlib.sha256()

    count = 0

    for ip in range(start_ip, end_ip + 1):
        if done.value:
            return

        a = ip >> 24
        b = (ip >> 16) & 0xFF
        c = (ip >> 8) & 0xFF
        d = ip & 0xFF

        data = "%d.%d.%d.%d" % (a, b, c, d)

        h256.update(data.encode())
        hash_result = h256.digest()

        if hash_result == target_hash:
            print(f"\nFound! IP: {data.decode()}")
            with done.get_lock():
                done.value = True
            return

        count += 1

        if count == 100000:
            with writer.processed_ips.get_lock():
                writer.processed_ips.value += count
                count = 0


def main():
    if len(sys.argv) != 2:
        print("Please provide a SHA-256 hash.")
        sys.exit(1)

    target_hash = bytes.fromhex(sys.argv[1])

    cores = os.cpu_count()

    min_ip = 0x00000000
    max_ip = 0xFFFFFFFF
    total_ips = max_ip - min_ip + 1

    step = total_ips // cores
    start_ip = min_ip

    now = time.time()

    writer = BarWriter(total_ips)
    progress_process = multiprocessing.Process(
        target=progressBarUpdater, args=(writer,))
    progress_process.start()

    processes = []
    for i in range(cores):
        end_ip = start_ip + step - 1

        # if it's the last process, give it the remaining IPs
        if i == cores - 1:
            end_ip = max_ip

        process = multiprocessing.Process(
            target=process_ips, args=(start_ip, end_ip, target_hash, writer))
        processes.append(process)
        process.start()
        start_ip += step

    for process in processes:
        process.join()

    with done.get_lock():
        done.value = True
    progress_process.join()

    print("\nElapsed:", time.time() - now)


if __name__ == "__main__":
    main()
