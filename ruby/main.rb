require 'digest'
require 'concurrent-ruby'

class U64Ptr
  attr_accessor :value

  def initialize(value)
    @value = value
    @mutex = Mutex.new
  end

  def increment(value)
    @mutex.synchronize do
      @value += value
    end
  end
end

hash = ARGV[0]
raise 'Missing hash argument' if hash.nil?

hash = [hash].pack('H*')

min_ip = 0x00000000
max_ip = 0xffffffff

cpus = Concurrent.processor_count - 1
total_ips = max_ip - min_ip + 1
step_size = (total_ips.to_f / cpus).ceil

ip = min_ip
tasks = []

now = Time.now

u64_ctr = 0
processed = U64Ptr.new(u64_ctr)

cpus.times do
  start_ip = ip
  end_ip = [ip + step_size - 1, max_ip].min

  task = Thread.new do
    hasher = Digest::SHA256.new
    data = '%d.%d.%d.%d'

    (start_ip..end_ip).each do |ip|
      ip_str = data % [((ip >> 24) & 0xff), ((ip >> 16) & 0xff), ((ip >> 8) & 0xff), (ip & 0xff)]
      hasher.reset
      hasher.update(ip_str)
      result = hasher.digest

      if result == hash
        ip_str = "#{(ip >> 24) & 0xff}.#{(ip >> 16) & 0xff}.#{(ip >> 8) & 0xff}.#{ip & 0xff}"
        puts "\nFound matching IP: #{ip_str}"
        break
      end

      if ip % 100_000 == 0
        processed.increment(100_000)
      end
    end
  end
  tasks << task

  ip = end_ip + 1
end

Thread.new do
  loop do
    processed_value = processed.value.to_f
    ips_per_sec = processed_value / (Time.now - now)

    progress = (processed_value / total_ips) * 100
    remaining_ips = total_ips - processed_value
    est_remaining_secs = remaining_ips / ips_per_sec
    print format("\r%d/%d IPs | %.2f IPs/sec | Progress: %.2f%% | ETA: %.2fs | Elapsed: %.2fs",
                 processed_value, total_ips, ips_per_sec, progress, est_remaining_secs, Time.now - now)

    break if processed_value >= total_ips

    sleep(0.1)
  end
end

tasks.each(&:join)
