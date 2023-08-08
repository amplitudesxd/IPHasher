package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
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
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(1024 * 1024 * 1024) // 1 GiB

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

	cores := runtime.NumCPU()   // Get the number of CPU cores available
	minIP := uint64(0x00000000) // Minimum IP address value
	maxIP := uint64(0xFFFFFFFF) // Maximum IP address value
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

	h256 := sha256.New()

	for ip := startIP; ip <= endIP; ip++ {
		if done {
			return
		}

		h256.Reset()
		ipString := byteToStringTable[byte(ip>>24)] + "." +
			byteToStringTable[byte(ip>>16)] + "." +
			byteToStringTable[byte(ip>>8)] + "." +
			byteToStringTable[byte(ip)]

		h256.Write([]byte(ipString))
		hash := h256.Sum(nil)

		if string(hash) == string(targetHash) {
			fmt.Printf("\nFound! IP: %s\n", ipString)
			done = true
			return
		}

		atomic.AddUint64(&writer.processedIPs, 1) // Increment the processedIPs field safely
	}
}

var byteToStringTable = [256]string{
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100", "101", "102", "103", "104", "105", "106", "107", "108", "109", "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122", "123", "124", "125", "126", "127", "128", "129", "130", "131", "132", "133", "134", "135", "136", "137", "138", "139", "140", "141", "142", "143", "144", "145", "146", "147", "148", "149", "150", "151", "152", "153", "154", "155", "156", "157", "158", "159", "160", "161", "162", "163", "164", "165", "166", "167", "168", "169", "170", "171", "172", "173", "174", "175", "176", "177", "178", "179", "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", "190", "191", "192", "193", "194", "195", "196", "197", "198", "199", "200", "201", "202", "203", "204", "205", "206", "207", "208", "209", "210", "211", "212", "213", "214", "215", "216", "217", "218", "219", "220", "221", "222", "223", "224", "225", "226", "227", "228", "229", "230", "231", "232", "233", "234", "235", "236", "237", "238", "239", "240", "241", "242", "243", "244", "245", "246", "247", "248", "249", "250", "251", "252", "253", "254", "255",
}
