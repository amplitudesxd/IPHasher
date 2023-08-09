package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var wg sync.WaitGroup
var done bool

type barWriter struct {
	totalIPs     uint64
	processedIPs atomic.Uint64
	startTime    time.Time
}

func (w *barWriter) updateProgressBar() {
	processedIPs := w.processedIPs.Load()

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

func (w *barWriter) startProgressBarUpdater() {
	for !done {
		w.updateProgressBar()
		time.Sleep(time.Second)
		fmt.Print("\r")
	}
}

func main() {
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(1024 * 1024 * 1024) // 1 GiB

	// Check for command line argument
	if len(os.Args) != 2 {
		fmt.Println("Please provide a SHA-256 hash.")
		os.Exit(1)
	}

	// Convert the provided hash from hex to byte slice
	targetHash, err := hex.DecodeString(os.Args[1])
	if err != nil {
		fmt.Println("Error decoding hash:", err)
		os.Exit(1)
	}

	cores := runtime.NumCPU()   // Get the number of CPU cores available
	minIP := uint64(0x00000000) // Minimum IP address value
	maxIP := uint64(0xFFFFFFFF) // Maximum IP address value
	totalIPs := maxIP - minIP + 1

	// Calculate the IP address range for each goroutine
	step := totalIPs / uint64(cores)
	startIP := minIP

	now := time.Now()

	writer := &barWriter{totalIPs: totalIPs, startTime: now}
	go writer.startProgressBarUpdater()

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

	h256 := sha256.New()

	// 1.1.1.1 = 7 bytes
	// 255.255.255.255 = 15 bytes
	// 15 - 7 + 1 = 9 length possibilities
	cache := make([][]byte, 9)

	for i := 7; i <= 15; i++ {
		cache[i-7] = make([]byte, i)
	}

	var count uint64

	for ip := startIP; ip <= endIP; ip++ {
		if done {
			return
		}

		a := byteToByteArrayStringTable[byte(ip>>24)]
		b := byteToByteArrayStringTable[byte(ip>>16)]
		c := byteToByteArrayStringTable[byte(ip>>8)]
		d := byteToByteArrayStringTable[byte(ip)]

		l := len(a) + len(b) + len(c) + len(d) + 3
		data := cache[l-7]
		index := 0

		addOctet(data, a, &index, true)
		addOctet(data, b, &index, true)
		addOctet(data, c, &index, true)
		addOctet(data, d, &index, false)

		h256.Reset()
		h256.Write(data)
		hash := h256.Sum(nil)

		if bytes.Equal(hash, targetHash) {
			fmt.Printf("\nFound! IP: %s\n", string(data))
			done = true
			return
		}

		count++

		if count == 100000 {
			writer.processedIPs.Add(count)
			count = 0
		}
	}
}

func addOctet(dst, src []byte, index *int, period bool) {
	for i := 0; i < len(src); i++ {
		dst[*index] = src[i]
		*index++
	}

	if period {
		dst[*index] = byte('.')
		*index++
	}
}

var byteToByteArrayStringTable = [256][]byte{}

func init() {
	for i := 0; i < 256; i++ {
		byteToByteArrayStringTable[i] = []byte(strconv.Itoa(i))
	}
}
