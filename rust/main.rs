use std::{
    env::args,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    let hash = args().nth(1).expect("Missing hash argument");
    let hash = hex::decode(hash)?;

    let min_ip = 0x00000000u64;
    let max_ip = 0xffffffffu64;

    let cpus = num_cpus::get() - 1;
    let total_ips = max_ip - min_ip + 1;
    let step_size = total_ips / cpus as u64;

    let mut ip = min_ip;
    let mut tasks = vec![];

    let now = Instant::now();
    let processed = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));

    for _ in 0..cpus {
        let start_ip = ip;
        let end_ip = ip + step_size - 1;

        let hash = hash.clone();
        let processed = processed.clone();
        let done = done.clone();

        let task = tokio::spawn(async move {
            let mut hasher = Sha256::new();
            let mut data = vec![];

            for ip in start_ip..=end_ip {
                if ip % 1000000 == 0 && done.load(Ordering::Relaxed) {
                    break;
                }

                data.clear();

                encode_digit(ip >> 24 & 0xff, &mut data);
                data.push(b'.');
                encode_digit(ip >> 16 & 0xff, &mut data);
                data.push(b'.');
                encode_digit(ip >> 8 & 0xff, &mut data);
                data.push(b'.');
                encode_digit(ip & 0xff, &mut data);

                hasher.update(&data);

                let result = hasher.finalize_reset();

                if result[..] == hash[..] {
                    let ip = format!(
                        "{}.{}.{}.{}",
                        ip >> 24 & 0xff,
                        ip >> 16 & 0xff,
                        ip >> 8 & 0xff,
                        ip & 0xff
                    );
                    println!("Found matching IP: {}", ip);
                    done.store(true, Ordering::Relaxed);
                    break;
                }

                processed.fetch_add(1, Ordering::Relaxed);
            }
        });
        tasks.push(task);

        ip += step_size;
    }

    let processed = processed.clone();
    tokio::spawn(async move {
        loop {
            let processed = processed.load(Ordering::Relaxed);
            let ips_per_sec = processed as f64 / now.elapsed().as_secs_f64();

            let progress = processed as f64 / total_ips as f64 * 100.0;
            let remaining_ips = total_ips - processed;
            let est_remaining_secs = remaining_ips as f64 / ips_per_sec;

            println!(
                "{}/{} IPs | {:.2} IPs/sec | Progress: {:.2}% | ETA: {:.2}s | Elapsed: {:.2}s",
                processed,
                total_ips,
                ips_per_sec,
                progress,
                est_remaining_secs,
                now.elapsed().as_secs_f64()
            );

            if done.load(Ordering::Relaxed) {
                break;
            }

            sleep(Duration::from_millis(100)).await;
        }
    });

    for task in tasks {
        task.await?;
    }

    Ok(())
}

#[inline(always)]
fn encode_digit(mut digit: u64, buf: &mut Vec<u8>) {
    if digit == 0 {
        buf.push(b'0');
        return;
    }

    let byte_count = if digit >= 100 {
        3
    } else if digit >= 10 {
        2
    } else {
        1
    };
    let mut index = buf.len() + byte_count - 1;

    for _ in 0..byte_count {
        buf.push(0);
    }

    while digit > 0 {
        buf[index] = b'0' + (digit % 10) as u8;
        digit /= 10;
        index -= 1;
    }
}
