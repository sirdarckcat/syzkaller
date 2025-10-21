package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/cyrus-and/gdb"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
)

// BuildResult holds the outcome of a kernel build.
type BuildResult struct {
	KernelImagePath string
	VmlinuxPath     string
	Err             error
}

// ExecutorConfig holds the configuration for the Executor.
type ExecutorConfig struct {
	SyzkallerPath   string
	KernelDir       string
	KernelCheckout  string
	DiskImage       string
	KernelBZImage   string
	Debug           bool
	BuildResultChan <-chan *BuildResult
}

// Executor provides methods for running programs and commands in a VM.
type Executor struct {
	cfg          ExecutorConfig
	buildResult  *BuildResult
	once         sync.Once
	activeHandle *programHandle
}

// NewExecutor creates a new Executor.
func NewExecutor(cfg ExecutorConfig) *Executor {
	return &Executor{cfg: cfg}
}

// OpenVMSession starts a new VM and connects a GDB server to it.
func (e *Executor) OpenVMSession() (string, error) {
	if e.activeHandle != nil {
		return "", fmt.Errorf("a VM session is already active. Please close it first with 'close_vm_session'")
	}
	e.checkBuildStatus()
	if e.buildResult != nil && e.buildResult.Err != nil {
		return "", fmt.Errorf("cannot open VM session because kernel build failed: %w", e.buildResult.Err)
	}
	kernelCheckout := e.cfg.KernelCheckout
	kernelBZImage := e.cfg.KernelBZImage
	if e.buildResult != nil && e.buildResult.VmlinuxPath != "" {
		kernelCheckout = e.buildResult.VmlinuxPath
		kernelBZImage = e.buildResult.KernelImagePath
	}
	if kernelCheckout == "" || kernelBZImage == "" {
		return "", fmt.Errorf("kernel checkout and kernel bzImage paths are not available to open the VM session")
	}

	socketFile, err := os.CreateTemp("", "syz-gdb-socket-")
	if err != nil {
		return "", fmt.Errorf("failed to create gdb socket file: %w", err)
	}
	gdbSocket := socketFile.Name()
	socketFile.Close()
	os.Remove(gdbSocket)

	var gdbInst *gdb.Gdb
	gdbNotifications := make(chan map[string]interface{}, 1)
	notificationHandler := func(notification map[string]interface{}) {
		if e.activeHandle == nil {
			return
		}
		var needsContinue bool
		e.activeHandle.mu.Lock()
		if e.activeHandle.isCapturingForCmd {
			e.activeHandle.cmdNotifications = append(e.activeHandle.cmdNotifications, notification)
		} else {
			e.activeHandle.notificationLog = append(e.activeHandle.notificationLog, notification)
			if e.activeHandle.isWaitingForGDB {
				e.activeHandle.pendingNotifications = append(e.activeHandle.pendingNotifications, notification)
				if class, ok := notification["class"].(string); ok && class == "stopped" {
					select {
					case e.activeHandle.gdbNotifications <- notification:
					default:
						log.Logf(0, "gdb notification channel is full, dropping notification")
					}
				}
			} else if class, ok := notification["class"].(string); ok && class == "stopped" {
				needsContinue = true
			}
		}
		e.activeHandle.mu.Unlock()

		if needsContinue && gdbInst != nil {
			_, err := gdbInst.Send("exec-continue")
			if err != nil {
				fmt.Printf("--- Failed to automatically continue GDB: %v ---\n", err)
			}
		}
	}
	gdbInst, err = gdb.New(notificationHandler)
	if err != nil {
		return "", fmt.Errorf("failed to create GDB instance: %w", err)
	}

	handle, err := e.prepareVM(kernelCheckout, kernelBZImage, gdbSocket)
	if err != nil {
		gdbInst.Exit()
		return "", fmt.Errorf("failed to prepare VM: %w", err)
	}

	if _, err := gdbInst.Send("target-select", "remote", gdbSocket); err != nil {
		handle.Close()
		gdbInst.Exit()
		return "", fmt.Errorf("failed to connect to GDB socket: %w", err)
	}
	if _, err := gdbInst.Send("file-symbol-file", handle.gdbInfo.VmlinuxPath); err != nil {
		handle.Close()
		gdbInst.Exit()
		return "", fmt.Errorf("failed to load symbol file: %w", err)
	}
	if _, err := gdbInst.Send("environment-directory", e.cfg.KernelDir); err != nil {
		handle.Close()
		gdbInst.Exit()
		return "", fmt.Errorf("failed to set environment directory: %w", err)
	}
	fromPath := "/syzkaller/managers/ci-upstream-bpf-kasan-gce/kernel"
	if _, err := gdbInst.Send("gdb-set", "substitute-path", fromPath, e.cfg.KernelDir); err != nil {
		handle.Close()
		gdbInst.Exit()
		return "", fmt.Errorf("failed to set substitute path: %w", err)
	}

	e.activeHandle = handle
	e.activeHandle.gdbInst = gdbInst
	e.activeHandle.gdbNotifications = gdbNotifications

	return "The VM finished booting. It is now possible to use `gdb_command` or run a syzkaller program.", nil
}

// GdbCommand executes a command in the active GDB session.
func (e *Executor) GdbCommand(command string) (string, error) {
	if e.activeHandle == nil || e.activeHandle.gdbInst == nil {
		return "", fmt.Errorf("no active GDB session. Please use 'open_vm_session' first")
	}

	e.activeHandle.mu.Lock()
	e.activeHandle.isCapturingForCmd = true
	e.activeHandle.cmdNotifications = nil
	e.activeHandle.mu.Unlock()

	result, err := e.activeHandle.gdbInst.Send("interpreter-exec", "console", command)

	e.activeHandle.mu.Lock()
	e.activeHandle.isCapturingForCmd = false
	notifications := e.activeHandle.cmdNotifications
	e.activeHandle.mu.Unlock()

	if err != nil {
		return "", fmt.Errorf("failed to execute GDB command '%s': %w", command, err)
	}
	response := map[string]any{"result": result, "notifications": notifications}
	jsonOutput, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal gdb output: %w", err)
	}
	return string(jsonOutput), nil
}

// GdbLog returns the log of all GDB notifications received during the current session.
func (e *Executor) GdbLog() (string, error) {
	if e.activeHandle == nil {
		return "", fmt.Errorf("no active GDB session. Please use 'open_vm_session' first")
	}
	e.activeHandle.mu.Lock()
	log := e.activeHandle.notificationLog
	e.activeHandle.mu.Unlock()

	jsonOutput, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal notification log: %w", err)
	}
	return string(jsonOutput), nil
}

// RunSyzProgram executes a syzkaller program in the currently running VM.
func (e *Executor) RunSyzProgram(syzProgram string) (string, error) {
	if e.activeHandle == nil || e.activeHandle.execInst == nil {
		return "", fmt.Errorf("no active VM session. Please use 'open_vm_session' first")
	}
	progFile, err := os.CreateTemp("", "syz-prog-*.syz")
	if err != nil {
		return "", fmt.Errorf("failed to create temp program file: %w", err)
	}
	defer os.Remove(progFile.Name())
	if _, err := progFile.WriteString(syzProgram); err != nil {
		return "", fmt.Errorf("failed to write to temp program file: %w", err)
	}
	progFile.Close()

	reproOpts, err := parseReproOptions(progFile.Name())
	if err != nil {
		return "", fmt.Errorf("failed to parse repro options: %w", err)
	}
	csOpts := buildCsourceOptions(reproOpts)

	if _, err := e.activeHandle.gdbInst.Send("exec-continue"); err != nil {
		return "", fmt.Errorf("failed to continue GDB before running program: %w", err)
	}

	go func() {
		result, err := e.activeHandle.execInst.RunSyzProgFile(progFile.Name(), 5*time.Minute, csOpts, instance.SyzExitConditions)
		if err != nil {
			fmt.Printf("\n--- Background syz program execution failed: %v ---\n", err)
			return
		}
		if result.Report != nil {
			fmt.Printf("\n--- CRASH DETECTED ---\nTitle: %s\n\n%s\n--------------------\n", result.Report.Title, result.Report.Report)
		}
	}()

	return "Syz program execution started in the background.", nil
}

// GdbSyzProgram executes a syzkaller program and waits for a GDB breakpoint or crash.
func (e *Executor) GdbSyzProgram(syzProgram string) (string, error) {
	if e.activeHandle == nil || e.activeHandle.execInst == nil {
		return "", fmt.Errorf("no active VM session. Please use 'open_vm_session' first")
	}
	progFile, err := os.CreateTemp("", "syz-prog-*.syz")
	if err != nil {
		return "", fmt.Errorf("failed to create temp program file: %w", err)
	}
	defer os.Remove(progFile.Name())
	if _, err := progFile.WriteString(syzProgram); err != nil {
		return "", fmt.Errorf("failed to write to temp program file: %w", err)
	}
	progFile.Close()

	reproOpts, err := parseReproOptions(progFile.Name())
	if err != nil {
		return "", fmt.Errorf("failed to parse repro options: %w", err)
	}
	csOpts := buildCsourceOptions(reproOpts)

	e.activeHandle.mu.Lock()
	e.activeHandle.isWaitingForGDB = true
	e.activeHandle.pendingNotifications = nil
	e.activeHandle.mu.Unlock()

	defer func() {
		e.activeHandle.mu.Lock()
		e.activeHandle.isWaitingForGDB = false
		e.activeHandle.pendingNotifications = nil
		e.activeHandle.mu.Unlock()
	}()

	go func() {
		if _, err := e.activeHandle.gdbInst.Send("exec-continue"); err != nil {
			log.Logf(0, "failed to continue gdb in gdb_syz_program: %v", err)
			return
		}
		_, err := e.activeHandle.execInst.RunSyzProgFile(progFile.Name(), 2*time.Minute, csOpts, instance.SyzExitConditions)
		if err != nil {
			log.Logf(0, "syz program execution failed in gdb_syz_program: %v", err)
		}
	}()

	select {
	case <-e.activeHandle.gdbNotifications:
		e.activeHandle.mu.Lock()
		notifications := e.activeHandle.pendingNotifications
		e.activeHandle.mu.Unlock()
		jsonOutput, err := json.MarshalIndent(notifications, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal notifications: %w", err)
		}
		return string(jsonOutput), nil
	case <-time.After(2 * time.Minute):
		return "", fmt.Errorf("timed out after 2 minutes of waiting for a GDB 'stopped' notification")
	}
}

// CloseVMSession closes the currently running VM and its associated GDB session.
func (e *Executor) CloseVMSession() (string, error) {
	if e.activeHandle == nil {
		return "No active VM session to close.", nil
	}
	e.activeHandle.Close()
	e.activeHandle = nil
	return "VM session closed successfully.", nil
}

// Pahole inspects a kernel data structure's layout using 'pahole'.
func (e *Executor) Pahole(name string) (string, error) {
	vmlinuxPath, err := e.getVmlinuxPath()
	if err != nil {
		return "", err
	}
	kernelObj, cleanup, err := HandleFileFlag(vmlinuxPath)
	if err != nil {
		return "", fmt.Errorf("failed to get local kernel object directory: %w", err)
	}
	defer cleanup()
	cmd := exec.Command("pahole", name, kernelObj)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pahole command failed: %v\nOutput: %s", err, string(output))
	}
	return string(output), nil
}

// Objdump gets the interleaved C source code and assembly for a function or symbol.
func (e *Executor) Objdump(symbolName string) (string, error) {
	vmlinuxPath, err := e.getVmlinuxPath()
	if err != nil {
		return "", err
	}
	kernelObj, cleanup, err := HandleFileFlag(vmlinuxPath)
	if err != nil {
		return "", fmt.Errorf("failed to get local kernel object directory: %w", err)
	}
	defer cleanup()
	args := []string{
		"--source-comment=/*C*/", "--prefix=" + e.cfg.KernelDir, "--prefix-strip=4",
		"--no-show-raw-insn", "--no-addresses", "--line-numbers", "--section=.text",
		fmt.Sprintf("--disassemble=%s", symbolName), kernelObj,
	}
	cmd := exec.Command("objdump", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("objdump command failed: %v\nOutput: %s", err, string(output))
	}
	return string(output), nil
}

// --- Internal Implementation ---

func (e *Executor) checkBuildStatus() {
	e.once.Do(func() {
		if e.cfg.BuildResultChan == nil {
			e.buildResult = &BuildResult{}
			return
		}
		result, ok := <-e.cfg.BuildResultChan
		if !ok {
			e.buildResult = &BuildResult{Err: fmt.Errorf("build channel was closed unexpectedly")}
			return
		}
		e.buildResult = result
	})
}

func (e *Executor) getVmlinuxPath() (string, error) {
	e.checkBuildStatus()
	if e.buildResult != nil && e.buildResult.Err != nil {
		return "", fmt.Errorf("cannot run because kernel build failed: %w", e.buildResult.Err)
	}
	vmlinuxPath := e.cfg.KernelCheckout
	if e.buildResult != nil && e.buildResult.VmlinuxPath != "" {
		vmlinuxPath = e.buildResult.VmlinuxPath
	}
	if vmlinuxPath == "" {
		return "", fmt.Errorf("vmlinux path is not available")
	}
	return vmlinuxPath, nil
}

type programHandle struct {
	execInst             *instance.ExecProgInstance
	pool                 *vm.Pool
	cleanups             []func()
	gdbInfo              *gdbInfo
	gdbInst              *gdb.Gdb
	gdbNotifications     chan map[string]interface{}
	isWaitingForGDB      bool
	isCapturingForCmd    bool
	mu                   sync.Mutex
	pendingNotifications []map[string]interface{}
	cmdNotifications     []map[string]interface{}
	notificationLog      []map[string]interface{}
}

func (h *programHandle) Close() {
	if h.gdbInst != nil {
		h.gdbInst.Exit()
	}
	if h.execInst != nil && h.execInst.VMInstance != nil {
		h.execInst.VMInstance.Close()
	}
	if h.pool != nil {
		h.pool.Close()
	}
	if h.gdbNotifications != nil {
		close(h.gdbNotifications)
	}
	for _, fn := range h.cleanups {
		fn()
	}
}

type gdbInfo struct {
	Socket      string
	Command     string
	VmlinuxPath string
}

func (e *Executor) prepareVM(kernelCheckout, kernelBZImage, gdbSocket string) (*programHandle, error) {
	var cleanups []func()
	cleanupGuard := func(cleanup func()) { cleanups = append(cleanups, cleanup) }
	defer func() {
		if r := recover(); r != nil {
			for _, fn := range cleanups {
				fn()
			}
			panic(r)
		}
	}()

	localImage, cleanupImage, err := HandleFileFlag(e.cfg.DiskImage)
	if err != nil {
		return nil, err
	}
	cleanupGuard(cleanupImage)

	localKernel, cleanupKernel, err := HandleFileFlag(kernelBZImage)
	if err != nil {
		return nil, err
	}
	cleanupGuard(cleanupKernel)

	localKernelObj, cleanupKernelObj, err := HandleKernelObj(kernelCheckout)
	if err != nil {
		return nil, err
	}
	cleanupGuard(cleanupKernelObj)

	vmlinuxPath := filepath.Join(localKernelObj, "vmlinux")
	gdbDetails := &gdbInfo{
		Socket:      gdbSocket,
		Command:     fmt.Sprintf("gdb %s -ex 'target remote %s'", vmlinuxPath, gdbSocket),
		VmlinuxPath: vmlinuxPath,
	}

	cfg, err := e.buildManagerConfig(localKernelObj, localImage, localKernel, gdbSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to build manager config: %w", err)
	}

	vmPool, err := vm.Create(cfg, e.cfg.Debug)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM pool: %w", err)
	}

	osutil.HandleInterrupts(vm.Shutdown)
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		vmPool.Close()
		return nil, fmt.Errorf("failed to create reporter: %w", err)
	}

	execInst, err := instance.CreateExecProgInstance(vmPool, 0, cfg, reporter, nil)
	if err != nil {
		vmPool.Close()
		return nil, fmt.Errorf("failed to create execprog instance: %w", err)
	}

	return &programHandle{execInst: execInst, pool: vmPool, cleanups: cleanups, gdbInfo: gdbDetails}, nil
}

func (e *Executor) buildManagerConfig(kernelObj, image, kernel, gdbSocket string) (*mgrconfig.Config, error) {
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
		Count: 1, Kernel: kernel, CPU: 2, Mem: 2048,
		Cmdline: "root=/dev/sda1 console=ttyS0", QemuArgs: qemuArgs,
	}
	vmJSON, err := json.Marshal(vmConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VM config: %w", err)
	}

	cfg := &mgrconfig.Config{
		RawTarget: "linux/amd64", HTTP: "0.0.0.0:54321", Workdir: e.cfg.SyzkallerPath,
		KernelObj: kernelObj, Image: image, Syzkaller: e.cfg.SyzkallerPath,
		Procs: 4, Type: "qemu", VM: vmJSON, SSHUser: "root",
		Cover: true, Reproduce: false, Sandbox: "none",
		Experimental: mgrconfig.Experimental{
			RemoteCover: true, CoverEdges: true, DescriptionsMode: "manual",
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
