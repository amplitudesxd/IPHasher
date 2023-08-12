use std::{env::args, sync::Arc, time::Instant};

use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::time::{sleep, Duration};

struct U64Ptr(*mut u64);

unsafe impl Sync for U64Ptr {}
unsafe impl Send for U64Ptr {}

struct BoolPtr(*mut bool);

unsafe impl Sync for BoolPtr {}
unsafe impl Send for BoolPtr {}

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

    let mut u64_ctr = 0u64;
    let mut bool_ctr = false;
    let processed = Arc::new(U64Ptr(&mut u64_ctr as *mut u64));
    let done = Arc::new(BoolPtr(&mut bool_ctr as *mut bool));

    for _ in 0..cpus {
        let start_ip = ip;
        let end_ip = if c == cpus - 1 {
            max_ip
        } else {
            ip + step_size - 1
        };

        let processed = processed.clone();
        let done = done.clone();
        let hash = hash.clone();
        let task = tokio::spawn(async move {
            let mut hasher = Sha256::new();
            let mut data = vec![];

            for (idx, ip) in (start_ip..=end_ip).enumerate() {
                if idx != 0 && idx % 1000000 == 0 && unsafe { *done.0 } {
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
                    println!("\nFound matching IP: {}", ip);
                    unsafe { *done.0 = true };
                    break;
                }

                if idx != 0 && idx % 100000 == 0 {
                    unsafe {
                        *processed.0 += 100000;
                    }
                }
            }
        });
        tasks.push(task);

        ip += step_size;
    }

    tokio::spawn(async move {
        loop {
            let processed = unsafe { *processed.0 };
            let ips_per_sec = processed as f64 / now.elapsed().as_secs_f64();

            let progress = processed as f64 / total_ips as f64 * 100.0;
            let remaining_ips = total_ips - processed;
            let est_remaining_secs = remaining_ips as f64 / ips_per_sec;

            print!(
                "\r{}/{} IPs | {:.2} IPs/sec | Progress: {:.2}% | ETA: {:.2}s | Elapsed: {:.2}s",
                processed,
                total_ips,
                ips_per_sec,
                progress,
                est_remaining_secs,
                now.elapsed().as_secs_f64()
            );

            if unsafe { *done.0 } {
                break;
            }

            sleep(Duration::from_millis(10)).await;
        }
    });

    for task in tasks {
        task.await?;
    }

    Ok(())
}

const DIGITS: [&[u8]; 256] = [
    b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9", b"10", b"11", b"12", b"13", b"14",
    b"15", b"16", b"17", b"18", b"19", b"20", b"21", b"22", b"23", b"24", b"25", b"26", b"27",
    b"28", b"29", b"30", b"31", b"32", b"33", b"34", b"35", b"36", b"37", b"38", b"39", b"40",
    b"41", b"42", b"43", b"44", b"45", b"46", b"47", b"48", b"49", b"50", b"51", b"52", b"53",
    b"54", b"55", b"56", b"57", b"58", b"59", b"60", b"61", b"62", b"63", b"64", b"65", b"66",
    b"67", b"68", b"69", b"70", b"71", b"72", b"73", b"74", b"75", b"76", b"77", b"78", b"79",
    b"80", b"81", b"82", b"83", b"84", b"85", b"86", b"87", b"88", b"89", b"90", b"91", b"92",
    b"93", b"94", b"95", b"96", b"97", b"98", b"99", b"100", b"101", b"102", b"103", b"104",
    b"105", b"106", b"107", b"108", b"109", b"110", b"111", b"112", b"113", b"114", b"115", b"116",
    b"117", b"118", b"119", b"120", b"121", b"122", b"123", b"124", b"125", b"126", b"127", b"128",
    b"129", b"130", b"131", b"132", b"133", b"134", b"135", b"136", b"137", b"138", b"139", b"140",
    b"141", b"142", b"143", b"144", b"145", b"146", b"147", b"148", b"149", b"150", b"151", b"152",
    b"153", b"154", b"155", b"156", b"157", b"158", b"159", b"160", b"161", b"162", b"163", b"164",
    b"165", b"166", b"167", b"168", b"169", b"170", b"171", b"172", b"173", b"174", b"175", b"176",
    b"177", b"178", b"179", b"180", b"181", b"182", b"183", b"184", b"185", b"186", b"187", b"188",
    b"189", b"190", b"191", b"192", b"193", b"194", b"195", b"196", b"197", b"198", b"199", b"200",
    b"201", b"202", b"203", b"204", b"205", b"206", b"207", b"208", b"209", b"210", b"211", b"212",
    b"213", b"214", b"215", b"216", b"217", b"218", b"219", b"220", b"221", b"222", b"223", b"224",
    b"225", b"226", b"227", b"228", b"229", b"230", b"231", b"232", b"233", b"234", b"235", b"236",
    b"237", b"238", b"239", b"240", b"241", b"242", b"243", b"244", b"245", b"246", b"247", b"248",
    b"249", b"250", b"251", b"252", b"253", b"254", b"255",
];

#[inline(always)]
fn encode_digit(digit: u64, buf: &mut Vec<u8>) {
    let bytes = DIGITS[digit as usize];
    buf.extend_from_slice(bytes);
}
