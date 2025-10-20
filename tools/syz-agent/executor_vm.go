package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
)

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

func (se *SyzExecutor) runProgram(progFile, kernelCheckout, kernelBZImage string) (*runResult, *gdbInfo, error) {
	handle, gdbDetails, err := se.prepareProgram(progFile, kernelCheckout, kernelBZImage)
	if err != nil {
		return nil, nil, err
	}
	defer handle.Close()

	if gdbDetails != nil {
		log.Logf(0, "GDB server will be available on a unix socket.")
		log.Logf(0, "To connect: %s", gdbDetails.Command)
	}

	result, err := runPreparedProgram(handle)
	if err != nil {
		return nil, gdbDetails, err
	}
	return result, gdbDetails, nil
}

func (se *SyzExecutor) prepareProgram(progFile, kernelCheckout, kernelBZImage string) (*programHandle, *gdbInfo, error) {
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

	localImage, cleanupImage, err := handleFileFlag(se.cfg.DiskImage)
	if err != nil {
		return nil, nil, err
	}
	cleanupGuard(cleanupImage)

	localKernel, cleanupKernel, err := handleFileFlag(kernelBZImage)
	if err != nil {
		return nil, nil, err
	}
	cleanupGuard(cleanupKernel)

	localKernelObjDir, cleanupKernelObj, err := handleKernelObj(kernelCheckout)
	if err != nil {
		return nil, nil, err
	}
	cleanupGuard(cleanupKernelObj)

	var gdbSocket string
	var gdbDetails *gdbInfo
	enableGDB := false
	if enableGDB {
		socketFile, err := os.CreateTemp("", "syz-gdb-socket-")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gdb socket file: %w", err)
		}
		gdbSocket = socketFile.Name()
		socketFile.Close()
		os.Remove(gdbSocket)

		vmlinuxPath := filepath.Join(localKernelObjDir, "vmlinux")
		gdbDetails = &gdbInfo{
			Socket:  gdbSocket,
			Command: fmt.Sprintf("gdb %s -ex 'target remote %s'", vmlinuxPath, gdbSocket),
		}
	}

	cfg, err := se.buildManagerConfig(localKernelObjDir, localImage, localKernel, gdbSocket)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build manager config: %w", err)
	}

	reproOpts, err := parseReproOptions(progFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse repro options: %w", err)
	}
	csOpts := buildCsourceOptions(reproOpts)

	vmPool, err := vm.Create(cfg, se.cfg.Debug)
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
		progFile: progFile,
		csOpts:   csOpts,
		pool:     vmPool,
		cleanups: cleanups,
	}

	return handle, gdbDetails, nil
}

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

func (se *SyzExecutor) buildManagerConfig(kernelObj, image, kernel, gdbSocket string) (*mgrconfig.Config, error) {
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
		CPU:      2,
		Mem:      2048,
		Cmdline:  "root=/dev/sda1 console=ttyS0",
		QemuArgs: qemuArgs,
	}
	vmJSON, err := json.Marshal(vmConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VM config: %w", err)
	}

	cfg := &mgrconfig.Config{
		RawTarget: "linux/amd64",
		HTTP:      "0.0.0.0:54321",
		Workdir:   se.cfg.SyzkallerPath,
		KernelObj: kernelObj,
		Image:     image,
		Syzkaller: se.cfg.SyzkallerPath,
		Procs:     4,
		Type:      "qemu",
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
