package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/log"
	"github.com/ulikunitz/xz"
)

const cacheDir = "/tmp/syz-run-cache"

// reproOpts represents the options extracted from a .syz file's comments.
type reproOpts map[string]interface{}

// downloadAndDecompress fetches a file from a URL and decompresses it if needed.
func downloadAndDecompress(url, destPath string) error {
	if _, err := os.Stat(destPath); err == nil {
		log.Logf(0, "using cached file for %s", url)
		return nil
	}

	log.Logf(0, "fetching file from URL: %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch from URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch from %s, status: %s", url, resp.Status)
	}

	var reader io.Reader = resp.Body
	if strings.HasSuffix(url, ".xz") {
		log.Logf(0, "decompressing .xz file for %s", url)
		reader, err = xz.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
	} else if strings.HasSuffix(url, ".gz") {
		log.Logf(0, "decompressing .gz file for %s", url)
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
	}

	outFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create cache file %s: %w", destPath, err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, reader); err != nil {
		return fmt.Errorf("failed to write to cache file %s: %w", destPath, err)
	}
	log.Logf(0, "cached decompressed file for %s", url)

	return nil
}

// getCacheKey generates a stable filesystem-friendly cache key from a URL.
func getCacheKey(url string) string {
	hash := sha1.Sum([]byte(url))
	return hex.EncodeToString(hash[:])
}

// HandleFileFlag handles a path that can be either local or a URL.
// If it's a URL, it downloads the file to a local cache and returns the path.
func HandleFileFlag(path string) (localPath string, cleanup func(), err error) {
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		return path, func() {}, nil
	}

	cachePath := filepath.Join(cacheDir, getCacheKey(path))
	err = downloadAndDecompress(path, cachePath)
	return cachePath, func() {}, err
}

// handleKernelObj is a special version of HandleFileFlag for the kernel object (vmlinux).
// It ensures the downloaded file is placed in a stable directory.
func handleKernelObj(path string) (localPath string, cleanup func(), err error) {
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		return path, func() {}, nil
	}

	// Create a stable directory based on the URL's hash.
	objDir := filepath.Join(cacheDir, getCacheKey(path)+"_obj")
	if err := os.MkdirAll(objDir, 0755); err != nil {
		return "", func() {}, fmt.Errorf("failed to create stable obj dir: %w", err)
	}

	vmlinuxPath := filepath.Join(objDir, "vmlinux")
	if err := downloadAndDecompress(path, vmlinuxPath); err != nil {
		return "", func() {}, err
	}

	// No cleanup needed, as this is a persistent cache directory.
	return objDir, func() {}, nil
}

// parseReproOptions reads a .syz file and parses the JSON options from its comments.
func parseReproOptions(filename string) (reproOpts, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open program file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			continue
		}
		jsonStr := strings.TrimSpace(line[1:])
		var opts reproOpts
		if err := json.Unmarshal([]byte(jsonStr), &opts); err == nil {
			log.Logf(0, "parsed repro options from program header")
			return opts, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading program file: %w", err)
	}

	log.Logf(0, "no repro options found in program header, using default flags")
	return reproOpts{}, nil
}

// buildCsourceOptions converts the parsed reproOpts into a csource.Options struct.
func buildCsourceOptions(opts reproOpts) csource.Options {
	getOpt := func(key string) (interface{}, bool) {
		if val, ok := opts[key]; ok {
			return val, true
		}
		if val, ok := opts[strings.ToLower(key)]; ok {
			return val, true
		}
		return nil, false
	}

	csOpts := csource.Options{}
	if val, ok := getOpt("Threaded"); ok && val == true {
		csOpts.Threaded = true
	}
	if val, ok := getOpt("Repeat"); ok && val == true {
		csOpts.Repeat = true
	}
	if val, ok := getOpt("Procs"); ok {
		if procs, ok := val.(float64); ok {
			csOpts.Procs = int(procs)
		}
	}
	if val, ok := getOpt("Sandbox"); ok {
		if sandbox, ok := val.(string); ok {
			csOpts.Sandbox = sandbox
		}
	}
	if val, ok := getOpt("SandboxArg"); ok {
		if arg, ok := val.(float64); ok {
			csOpts.SandboxArg = int(arg)
		}
	}
	if val, ok := getOpt("NetInjection"); ok && val == true {
		csOpts.NetInjection = true
	}
	if val, ok := getOpt("NetDevices"); ok && val == true {
		csOpts.NetDevices = true
	}
	if val, ok := getOpt("NetReset"); ok && val == true {
		csOpts.NetReset = true
	}
	if val, ok := getOpt("Cgroups"); ok && val == true {
		csOpts.Cgroups = true
	}
	if val, ok := getOpt("BinfmtMisc"); ok && val == true {
		csOpts.BinfmtMisc = true
	}
	if val, ok := getOpt("CloseFDs"); ok && val == true {
		csOpts.CloseFDs = true
	}
	if val, ok := getOpt("DevlinkPCI"); ok && val == true {
		csOpts.DevlinkPCI = true
	}
	if val, ok := getOpt("VhciInjection"); ok && val == true {
		csOpts.VhciInjection = true
	}
	if val, ok := getOpt("Wifi"); ok && val == true {
		csOpts.Wifi = true
	}
	return csOpts
}

// printToolOutputPreview prints the first 30 lines of a tool's output to the console.
func printToolOutputPreview(toolName, output string) {
	fmt.Printf("\n--- Tool Output Preview: %s ---\n", toolName)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for i := 0; i < 30 && scanner.Scan(); i++ {
		fmt.Println(scanner.Text())
	}
	if scanner.Scan() {
		fmt.Println("... (output continues)")
	}
	fmt.Println("---------------------------------")
}
