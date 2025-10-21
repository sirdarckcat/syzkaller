package main

import (
	"encoding/json"
	"fmt"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
)

// prepareVM sets up and boots a new VM instance for program execution and GDB.
func (se *SyzExecutor) prepareVM(kernelCheckout, kernelBZImage, gdbSocket string) (*programHandle, error) {
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

	localImage, cleanupImage, err := HandleFileFlag(se.cfg.DiskImage)
	if err != nil {
		return nil, err
	}
	cleanupGuard(cleanupImage)

	localKernel, cleanupKernel, err := HandleFileFlag(kernelBZImage)
	if err != nil {
		return nil, err
	}
	cleanupGuard(cleanupKernel)

	localKernelObj, cleanupKernelObj, err := handleKernelObj(kernelCheckout)
	if err != nil {
		return nil, err
	}
	cleanupGuard(cleanupKernelObj)

	gdbDetails, err := createGDBInfo(localKernelObj, gdbSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to create GDB info: %w", err)
	}

	cfg, err := se.buildManagerConfig(localKernelObj, localImage, localKernel, gdbSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to build manager config: %w", err)
	}

	vmPool, err := vm.Create(cfg, se.cfg.Debug)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM pool: %w", err)
	}

	osutil.HandleInterrupts(vm.Shutdown)
	log.Logf(0, "booting a single VM...")

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

	handle := &programHandle{
		execInst: execInst,
		pool:     vmPool,
		cleanups: cleanups,
		gdbInfo:  gdbDetails,
	}

	return handle, nil
}

// buildManagerConfig constructs the necessary syzkaller manager configuration.
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
