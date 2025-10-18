// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
	"github.com/ulikunitz/xz"
)

var (
	// Flags for dynamically generating the manager config.
	flagSyzkallerPath = flag.String("syzkaller_path", "", "path to syzkaller checkout")
	flagKernelObj     = flag.String("kernel_obj", "", "path to kernel build directory or vmlinux URL")
	flagImage         = flag.String("image", "", "path to disk image file or URL")
	flagKernel        = flag.String("kernel", "", "path to kernel image (e.g., bzImage) or URL")
	flagVMType        = flag.String("type", "qemu", "VM type (e.g., qemu, gce)")
	flagProcs         = flag.Int("procs", 4, "number of parallel processes")
	flagCPU           = flag.Int("cpu", 2, "number of CPUs per VM")
	flagMem           = flag.Int("mem", 2048, "memory per VM in MB")
	flagTarget        = flag.String("target", "linux/amd64", "target OS/arch")
	flagDebug         = flag.Bool("debug", false, "enable debug output for VM and executor")
	flagGDB           = flag.Bool("gdb", false, "start a GDB server on a unix socket")
)

// reproOpts uses a map to handle different keys from different syzkaller versions.
type reproOpts map[string]interface{}

const cacheDir = "/tmp/syz-run-cache"

// programHandle holds the state required to execute a prepared program.
type programHandle struct {
	execInst *instance.ExecProgInstance
	progFile string
	csOpts   csource.Options
	pool     *vm.Pool
	cleanups []func()
}

func (h *programHandle) Close() {
	h.execInst.VMInstance.Close()
	h.pool.Close()
	for _, fn := range h.cleanups {
		fn()
	}
}

// gdbInfo holds the details needed to connect a GDB client.
type gdbInfo struct {
	Socket  string
	Command string
}

// runResult holds the final result of the program execution.
type runResult struct {
	Output []byte
	Report *report.Report
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		log.Fatalf("usage: syz-run [flags] my_program.syz")
	}
	if *flagSyzkallerPath == "" || *flagKernelObj == "" || *flagImage == "" || *flagKernel == "" {
		log.Fatalf("the -syzkaller_path, -kernel_obj, -image, and -kernel flags are required")
	}

	// Ensure the cache directory exists.
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Fatalf("failed to create cache directory: %v", err)
	}

	progFile := flag.Args()[0]
	err := runProgram(*flagTarget, *flagSyzkallerPath, *flagKernelObj, *flagImage, *flagKernel, *flagVMType,
		progFile, *flagProcs, *flagCPU, *flagMem, *flagDebug, *flagGDB)
	if err != nil {
		log.Fatalf("%v", err)
	}
}

// runProgram orchestrates the prepare and run phases.
func runProgram(target, syzkallerPath, kernelObj, image, kernel, vmType, progFile string, procs, cpu, mem int, debug, gdb bool) error {
	handle, gdbDetails, err := prepareProgram(target, syzkallerPath, kernelObj, image, kernel, vmType,
		progFile, procs, cpu, mem, debug, gdb)
	if err != nil {
		return err
	}
	defer handle.Close()

	if gdbDetails != nil {
		log.Logf(0, "GDB server will be available on a unix socket.")
		log.Logf(0, "To connect: %s", gdbDetails.Command)
	}

	result, err := runPreparedProgram(handle)
	if err != nil {
		return err
	}

	log.Logf(0, "execution finished.")
	fmt.Printf("\n--- VM OUTPUT ---\n%s\n-----------------\n", result.Output)

	if result.Report == nil {
		log.Logf(0, "no crash detected in the output")
		return nil
	}

	log.Logf(0, "crash detected!")
	fmt.Printf("\n--- CRASH REPORT ---\n")
	fmt.Printf("Title: %s\n\n", result.Report.Title)
	fmt.Printf("%s\n\n", result.Report.Report)
	fmt.Printf("--------------------\n")

	return nil
}

// prepareProgram sets up the VM and all necessary configs, but does not run the syz program.
func prepareProgram(target, syzkallerPath, kernelObj, image, kernel, vmType, progFile string, procs, cpu, mem int, debug, gdb bool) (*programHandle, *gdbInfo, error) {
	var cleanups []func()
	cleanupGuard := func(cleanup func()) {
		cleanups = append(cleanups, cleanup)
	}
	defer func() {
		if r := recover(); r != nil {
			for _, fn := range cleanups {
				fn()
			}
			panic(r)
		}
	}()

	localProgFile, cleanup, err := handleFileFlag(progFile, "syz-prog-*.syz")
	if err != nil {
		return nil, nil, err
	}
	cleanupGuard(cleanup)

	localImage, cleanupImage, err := handleFileFlag(image, "syz-image-*")
	if err != nil {
		return nil, nil, err
	}
	cleanupGuard(cleanupImage)

	localKernel, cleanupKernel, err := handleFileFlag(kernel, "syz-kernel-*")
	if err != nil {
		return nil, nil, err
	}
	cleanupGuard(cleanupKernel)

	localKernelObj, cleanupKernelObj, err := handleKernelObj(kernelObj)
	if err != nil {
		return nil, nil, err
	}
	cleanupGuard(cleanupKernelObj)

	var gdbSocket string
	var gdbDetails *gdbInfo
	if gdb {
		socketFile, err := os.CreateTemp("", "syz-gdb-socket-")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gdb socket file: %w", err)
		}
		gdbSocket = socketFile.Name()
		socketFile.Close()
		os.Remove(gdbSocket) // We only need the unique path, not the file itself.

		vmlinuxPath := filepath.Join(localKernelObj, "vmlinux")
		gdbDetails = &gdbInfo{
			Socket:  gdbSocket,
			Command: fmt.Sprintf("gdb %s -ex 'target remote %s'", vmlinuxPath, gdbSocket),
		}
	}

	cfg, err := buildManagerConfig(target, syzkallerPath, localKernelObj, localImage, localKernel, vmType, procs, cpu, mem, debug, gdbSocket)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build manager config: %w", err)
	}

	reproOpts, err := parseReproOptions(localProgFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse repro options: %w", err)
	}
	csOpts := buildCsourceOptions(reproOpts)

	vmPool, err := vm.Create(cfg, debug)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create VM pool: %w", err)
	}

	osutil.HandleInterrupts(vm.Shutdown)
	log.Logf(0, "booting a single VM...")

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		vmPool.Close()
		return nil, nil, fmt.Errorf("failed to create reporter: %w", err)
	}

	execInst, err := instance.CreateExecProgInstance(vmPool, 0, cfg, reporter, nil)
	if err != nil {
		vmPool.Close()
		return nil, nil, fmt.Errorf("failed to create execprog instance: %w", err)
	}

	handle := &programHandle{
		execInst: execInst,
		progFile: localProgFile,
		csOpts:   csOpts,
		pool:     vmPool,
		cleanups: cleanups,
	}

	return handle, gdbDetails, nil
}

// runPreparedProgram executes the syz program using the prepared handle.
func runPreparedProgram(handle *programHandle) (*runResult, error) {
	result, err := handle.execInst.RunSyzProgFile(handle.progFile, 5*time.Minute, handle.csOpts, instance.SyzExitConditions)
	if err != nil {
		return nil, fmt.Errorf("program execution failed: %w", err)
	}
	return &runResult{
		Output: result.Output,
		Report: result.Report,
	}, nil
}

// downloadAndDecompress fetches a URL, decompresses it if necessary, and writes to a destination file.
func downloadAndDecompress(url, destPath string) error {
	cacheKey := getCacheKey(url)
	if _, err := os.Stat(cacheKey); err == nil {
		log.Logf(0, "using cached file for %s", url)
		return osutil.CopyFile(cacheKey, destPath)
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
	}

	// Write to the cache file directly.
	cacheFile, err := os.Create(cacheKey)
	if err != nil {
		return fmt.Errorf("failed to create cache file %s: %w", cacheKey, err)
	}
	defer cacheFile.Close()

	if _, err := io.Copy(cacheFile, reader); err != nil {
		return fmt.Errorf("failed to write to cache file %s: %w", cacheKey, err)
	}
	log.Logf(0, "cached decompressed file for %s", url)

	// Now copy from the cache to the final destination.
	return osutil.CopyFile(cacheKey, destPath)
}

// handleFileFlag manages a file specified by a flag, downloading it if it's a URL.
func handleFileFlag(path, pattern string) (localPath string, cleanup func(), err error) {
	cleanup = func() {} // Default to no-op cleanup.
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		return path, cleanup, nil
	}

	tempPattern := strings.Replace(pattern, ".xz", "", 1)
	tempFile, err := os.CreateTemp("", tempPattern)
	if err != nil {
		return "", cleanup, fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempFile.Close()

	if err := downloadAndDecompress(path, tempFile.Name()); err != nil {
		os.Remove(tempFile.Name())
		return "", cleanup, err
	}

	return tempFile.Name(), func() { os.Remove(tempFile.Name()) }, nil
}

// handleKernelObj manages the kernel object, downloading it to a temp directory if it's a URL.
func handleKernelObj(path string) (localPath string, cleanup func(), err error) {
	cleanup = func() {}
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		return path, cleanup, nil
	}

	tempDir, err := os.MkdirTemp("", "syz-kernel-obj-")
	if err != nil {
		return "", cleanup, fmt.Errorf("failed to create temp dir for kernel_obj: %w", err)
	}

	vmlinuxPath := filepath.Join(tempDir, "vmlinux")
	if err := downloadAndDecompress(path, vmlinuxPath); err != nil {
		os.RemoveAll(tempDir)
		return "", cleanup, err
	}

	return tempDir, func() { os.RemoveAll(tempDir) }, nil
}

func getCacheKey(url string) string {
	hash := sha1.Sum([]byte(url))
	return filepath.Join(cacheDir, hex.EncodeToString(hash[:]))
}

func buildManagerConfig(target, syzkallerPath, kernelObj, image, kernel, vmType string, procs, cpu, mem int, debug bool, gdbSocket string) (*mgrconfig.Config, error) {
	qemuArgs := "-machine pc-q35-7.1 -enable-kvm"
	if gdbSocket != "" {
		qemuArgs += fmt.Sprintf(" -chardev socket,path=%s,server=on,wait=off,id=gdb0 -gdb chardev:gdb0", gdbSocket)
	}

	vmConfig := struct {
		Count    int    `json:"count"`
		Kernel   string `json:"kernel"`
		CPU      int    `json:"cpu"`
		Mem      int    `json:"mem"`
		Cmdline  string `json:"cmdline"`
		QemuArgs string `json:"qemu_args"`
	}{
		Count:    1,
		Kernel:   kernel,
		CPU:      cpu,
		Mem:      mem,
		Cmdline:  "root=/dev/sda1 console=ttyS0",
		QemuArgs: qemuArgs,
	}
	vmJSON, err := json.Marshal(vmConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VM config: %w", err)
	}

	cfg := &mgrconfig.Config{
		RawTarget: target,
		HTTP:      "0.0.0.0:54321",
		Workdir:   syzkallerPath,
		KernelObj: kernelObj,
		Image:     image,
		Syzkaller: syzkallerPath,
		Procs:     procs,
		Type:      vmType,
		VM:        vmJSON,
		SSHUser:   "root",
		Cover:     true,
		Reproduce: false,
		Sandbox:   "none",
		Experimental: mgrconfig.Experimental{
			RemoteCover:      true,
			CoverEdges:       true,
			DescriptionsMode: "manual",
		},
	}
	if err := mgrconfig.SetTargets(cfg); err != nil {
		return nil, fmt.Errorf("failed to set target config: %w", err)
	}
	if err := mgrconfig.Complete(cfg); err != nil {
		return nil, fmt.Errorf("failed to complete config: %w", err)
	}
	return cfg, nil
}

// parseReproOptions reads a .syz file and parses the first valid JSON config from comments.
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

// buildCsourceOptions constructs csource.Options from the parsed repro options.
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

	// Mapping for boolean feature flags.
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
