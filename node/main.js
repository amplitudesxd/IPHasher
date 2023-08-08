const crypto = require('crypto');
const {
  Worker,
  isMainThread,
  parentPort,
  workerData,
} = require('worker_threads');

class ProgressBar {
  constructor(totalIPs) {
    this.totalIPs = totalIPs;
    this.processedIPs = 0;
    this.startTime = new Date();
  }

  update() {
    const processedIPs = this.processedIPs;

    const ipsPerSec = processedIPs / ((new Date() - this.startTime) / 1000);
    const ipsPerSecFormatted = isFinite(ipsPerSec)
      ? ipsPerSec.toFixed(2)
      : '0.00';

    const progress = (processedIPs / this.totalIPs) * 100;

    const ipsRemaining = this.totalIPs - processedIPs;
    const estimatedTimeRemaining = ipsRemaining / ipsPerSec;

    console.log(
      `${processedIPs}/${
        this.totalIPs
      } IPs | ${ipsPerSecFormatted} IPs/sec | Progress: ${progress.toFixed(
        2
      )}% | ETA: ${estimatedTimeRemaining.toFixed()} s | Elapsed: ${(
        (new Date() - this.startTime) /
        1000
      ).toFixed(2)} s`
    );
  }
}

if (isMainThread) {
  const targetHash = process.argv[2]
    ? Buffer.from(process.argv[2], 'hex')
    : null;
  if (!targetHash) {
    console.log('Please provide a SHA256 hash.');
    process.exit(1);
  }

  const totalIPs = 0xffffffff - 0x00000000 + 1;
  const writer = new ProgressBar(totalIPs);

  const cores = require('os').cpus().length;
  const step = Math.floor(totalIPs / cores);
  let startIP = 0x00000000;

  const workerPromises = [];
  const workers = [];

  for (let i = 0; i < cores; i++) {
    const endIP = startIP + step - 1;
    const workerPromise = new Promise((resolve, reject) => {
      const worker = new Worker(__filename, {
        workerData: { startIP, endIP, targetHash },
      });

      workers.push(worker);

      worker.on('message', (message) => {
        if (message === 'done') {
          resolve();
          workers.forEach((worker) => worker.terminate());
        } else if (message.startsWith('processedIPs:')) {
          writer.processedIPs += parseInt(message.split(':')[1]);
        }
      });

      worker.on('error', reject);
      worker.on('exit', (code) => {
        if (code !== 0) {
          reject(new Error(`Worker stopped with exit code ${code}`));
        }
      });
    });

    workerPromises.push(workerPromise);
    startIP += step;
  }

  Promise.all(workerPromises).then(() => {
    console.log(
      `\nElapsed: ${((new Date() - writer.startTime) / 1000).toFixed(2)} s`
    );
  });

  const printProgressBar = () => {
    writer.update();
    setTimeout(printProgressBar, 100);
  };

  printProgressBar();
} else {
  const { startIP, endIP, targetHash } = workerData;

  let processedIPs = 0;
  const BATCH_SIZE = 1000;

  for (let ip = startIP; ip <= endIP; ip++) {
    const h512 = crypto.createHash('sha256');
    h512.update(
      `${(ip >> 24) & 0xff}.${(ip >> 16) & 0xff}.${(ip >> 8) & 0xff}.${
        ip & 0xff
      }`
    );
    const hash = h512.digest();

    if (hash.equals(targetHash)) {
      console.log(
        `Found! IP: ${(ip >> 24) & 0xff}.${(ip >> 16) & 0xff}.${
          (ip >> 8) & 0xff
        }.${ip & 0xff}`
      );
      parentPort.postMessage('done');
      break;
    }

    processedIPs++;

    if (processedIPs % BATCH_SIZE === 0) {
      parentPort.postMessage(`processedIPs:${processedIPs}`);
      processedIPs = 0;
    }
  }
}
