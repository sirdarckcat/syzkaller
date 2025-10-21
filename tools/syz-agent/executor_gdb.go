package main

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cyrus-and/gdb"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/vm"
)

// programHandle holds the state for an active VM and GDB session.
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

// Close gracefully shuts down the VM, GDB instance, and cleans up resources.
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

// gdbInfo holds the necessary details for a GDB connection.
type gdbInfo struct {
	Socket      string
	Command     string
	VmlinuxPath string
}

// createGDBInfo generates the GDB connection details from the kernel object path.
func createGDBInfo(kernelObjPath, gdbSocket string) (*gdbInfo, error) {
	vmlinuxPath := filepath.Join(kernelObjPath, "vmlinux")
	if vmlinuxPath == "" {
		return nil, fmt.Errorf("vmlinux path could not be determined from kernel object path '%s'", kernelObjPath)
	}
	return &gdbInfo{
		Socket:      gdbSocket,
		Command:     fmt.Sprintf("gdb %s -ex 'target remote %s'", vmlinuxPath, gdbSocket),
		VmlinuxPath: vmlinuxPath,
	}, nil
}
