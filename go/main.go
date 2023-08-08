package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var wg sync.WaitGroup
var done bool

type barWriter struct {
	totalIPs     uint64
	processedIPs uint64
	startTime    time.Time
}

func (w *barWriter) updateProgressBar() {
	processedIPs := atomic.LoadUint64(&w.processedIPs)

	ipsPerSec := float64(processedIPs) / time.Since(w.startTime).Seconds()
	if math.IsInf(ipsPerSec, 1) {
		ipsPerSec = 0
	}

	progress := float64(processedIPs) / float64(w.totalIPs) * 100

	ipsRemaining := w.totalIPs - processedIPs
	estimatedTimeRemaining := time.Duration(float64(ipsRemaining)/ipsPerSec) * time.Second

	fmt.Printf("%d/%d IPs | %.2f IPs/sec | Progress: %.2f%% | ETA: %s | Elapsed: %s ",
		processedIPs, w.totalIPs, ipsPerSec, progress, estimatedTimeRemaining.Round(time.Second), time.Since(w.startTime).Round(time.Second))
}

func printProgressBar(writer *barWriter) {
	for {
		if done {
			return
		}

		writer.updateProgressBar()
		time.Sleep(time.Millisecond * 100)
		fmt.Print("\r")
	}
}

func main() {
	now := time.Now()

	// Check for command line argument
	if len(os.Args) != 2 {
		fmt.Println("Please provide a SHA256 hash.")
		os.Exit(1)
	}

	// Convert the provided hash from hex to byte slice
	targetHash, err := hex.DecodeString(os.Args[1])
	if err != nil {
		fmt.Println("Error decoding hash:", err)
		os.Exit(1)
	}

	cores := runtime.NumCPU()                  // Get the number of CPU cores available
	minIP := uint64(0x00000000)                // Minimum IP address value
	maxIP := uint64(0xFFFFFFFF)                // Maximum IP address value
	totalIPs := maxIP - minIP + 1
	writer := &barWriter{totalIPs, 0, time.Now()}

	go printProgressBar(writer)

	// Calculate the IP address range for each goroutine
	step := totalIPs / uint64(cores)
	startIP := minIP

	// Launch goroutines based on the number of CPU cores
	for i := 0; i < cores; i++ {
		wg.Add(1)
		endIP := startIP + step - 1
		go processIPs(startIP, endIP, targetHash, writer)
		startIP += step
	}

	// Wait for all goroutines to finish
	wg.Wait()

	fmt.Println("\nElapsed:", time.Since(now))
}

func processIPs(startIP, endIP uint64, targetHash []byte, writer *barWriter) {
	defer wg.Done()

	h512 := sha256.New()

	for ip := startIP; ip <= endIP; ip++ {
		if done {
			return
		}
		
		h512.Reset()
		ipString := fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
		h512.Write([]byte(ipString))
		hash := h512.Sum(nil)

		if string(hash) == string(targetHash) {
			fmt.Printf("\nFound! IP: %d.%d.%d.%d\n", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
			done = true
			return
		}

		atomic.AddUint64(&writer.processedIPs, 1) // Increment the processedIPs field safely
	}
}
