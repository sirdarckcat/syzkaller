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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cyrus-and/gdb"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm"
	"github.com/ulikunitz/xz"
	"google.golang.org/genai"
)

// BuildResult holds the outcome of a kernel build.
type BuildResult struct {
	KernelImagePath string
	VmlinuxPath     string
	Err             error
}

// SyzExecutorConfig holds the configuration for the SyzExecutor tool provider.
type SyzExecutorConfig struct {
	SyzkallerPath   string
	KernelDir       string
	KernelCheckout  string
	DiskImage       string
	KernelBZImage   string
	Debug           bool
	BuildResultChan <-chan *BuildResult
}

// SyzExecutor provides tools for running syzkaller programs in a VM.
type SyzExecutor struct {
	cfg          SyzExecutorConfig
	buildResult  *BuildResult
	once         sync.Once
	activeHandle *programHandle
}

// NewSyzExecutor creates a new SyzExecutor.
func NewSyzExecutor(cfg SyzExecutorConfig) *SyzExecutor {
	return &SyzExecutor{cfg: cfg}
}

func logFunctionCall(name string, fc *genai.FunctionCall) {
	args, err := json.MarshalIndent(fc.Args, "", "  ")
	if err != nil {
		fmt.Printf("--- Calling %s (failed to marshal args: %v) ---\n", name, err)
		return
	}
	fmt.Printf("--- Calling %s with args ---\n%s\n---------------------------\n", name, string(args))
}

// GetTools returns the set of tools for the SyzExecutor.
func (se *SyzExecutor) GetTools() []*Tool {
	return []*Tool{
		{
			Declaration: genai.FunctionDeclaration{
				Name: "open_vm_session",
				Description: "Starts a new VM and connects a GDB server to it. The VM is left in a halted state. " +
					"Use 'gdb_command' with the 'continue' command to start execution.",
				Parameters: &genai.Schema{Type: genai.TypeObject},
			},
			Handler: se.handleOpenVMSession,
			Classes: []string{"syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "run_syz_program",
				Description: "Executes a syzkaller program in the currently running VM. This tool runs in the background. " +
					"A VM session must be opened first with 'open_vm_session'.",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"syz_program": {
							Type:        genai.TypeString,
							Description: "The full content of the .syz syzkaller program to execute.",
						},
					},
					Required: []string{"syz_program"},
				},
			},
			Handler: se.handleRunSyzProgram,
			Classes: []string{"crash_analyzer", "syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name:        "gdb_syz_program",
				Description: "Executes a syzkaller program and waits for a GDB breakpoint or crash, returning all GDB notifications.",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"syz_program": {
							Type:        genai.TypeString,
							Description: "The full content of the .syz syzkaller program to execute.",
						},
					},
					Required: []string{"syz_program"},
				},
			},
			Handler: se.handleGdbSyzProgram,
			Classes: []string{"crash_analyzer", "syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "gdb_command",
				Description: "Executes a command in the active GDB session using the MI 'interpreter-exec' command. " +
					"A session must be started with 'open_vm_session'. Key commands include 'continue', 'bt', 'info registers'.",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"command": {
							Type:        genai.TypeString,
							Description: "The GDB console command to execute.",
						},
					},
					Required: []string{"command"},
				},
			},
			Handler: se.handleGdbCommand,
			Classes: []string{"crash_analyzer", "syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name:        "gdb_log",
				Description: "Returns the log of all GDB notifications received during the current session.",
				Parameters:  &genai.Schema{Type: genai.TypeObject},
			},
			Handler: se.handleGdbLog,
			Classes: []string{"syzkaller_executor", "crash_analyzer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name:        "close_vm_session",
				Description: "Closes the currently running VM and its associated GDB session.",
				Parameters:  &genai.Schema{Type: genai.TypeObject},
			},
			Handler: se.handleCloseVMSession,
			Classes: []string{"syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "pahole",
				Description: "Inspects a kernel data structure's layout using 'pahole'. " +
					"Requires a built kernel with debug symbols (vmlinux).",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"name": {
							Type:        genai.TypeString,
							Description: "The name of the class or struct to inspect.",
						},
					},
					Required: []string{"name"},
				},
			},
			Handler: se.handlePahole,
			Classes: []string{"crash_analyzer", "code_explorer", "syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "objdump",
				Description: "Gets the interleaved C source code and assembly for a function or symbol from the kernel binary " +
					"using 'objdump'. Requires a built kernel with debug symbols (vmlinux).",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"symbol_name": {
							Type:        genai.TypeString,
							Description: "The name of the function or symbol to disassemble.",
						},
					},
					Required: []string{"symbol_name"},
				},
			},
			Handler: se.handleObjdump,
			Classes: []string{"crash_analyzer", "code_explorer", "syzkaller_executor"},
		},
	}
}

func (se *SyzExecutor) handleOpenVMSession(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	logFunctionCall("open_vm_session", fc)
	if se.activeHandle != nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "open_vm_session",
				Response: map[string]any{"error": "A VM session is already active. Please close it first with 'close_vm_session'."},
			},
		}, nil
	}
	se.checkBuildStatus()
	if se.buildResult != nil && se.buildResult.Err != nil {
		return nil, fmt.Errorf("cannot open VM session because kernel build failed: %w", se.buildResult.Err)
	}
	kernelCheckout := se.cfg.KernelCheckout
	kernelBZImage := se.cfg.KernelBZImage
	if se.buildResult != nil && se.buildResult.VmlinuxPath != "" {
		kernelCheckout = se.buildResult.VmlinuxPath
		kernelBZImage = se.buildResult.KernelImagePath
	}
	if kernelCheckout == "" || kernelBZImage == "" {
		return nil, fmt.Errorf("kernel checkout and kernel bzImage paths are not available to open the VM session")
	}

	// 1. Create GDB socket path first.
	socketFile, err := os.CreateTemp("", "syz-gdb-socket-")
	if err != nil {
		return nil, fmt.Errorf("failed to create gdb socket file: %w", err)
	}
	gdbSocket := socketFile.Name()
	socketFile.Close()
	os.Remove(gdbSocket) // The GDB server (QEMU) will create it.

	// 2. Initialize GDB instance.
	var gdbInst *gdb.Gdb
	gdbNotifications := make(chan map[string]interface{}, 1)
	notificationHandler := func(notification map[string]interface{}) {
		fmt.Println("--- GDB Notification Received ---")
		jsonNotification, _ := json.MarshalIndent(notification, "", "  ")
		fmt.Printf("--- Notification Content ---\n%s\n--------------------------\n", string(jsonNotification))

		if se.activeHandle == nil {
			fmt.Println("--- Received unexpected GDB notification (no active handle) ---")
			return
		}

		var needsContinue bool
		se.activeHandle.mu.Lock()

		if se.activeHandle.isCapturingForCmd {
			se.activeHandle.cmdNotifications = append(se.activeHandle.cmdNotifications, notification)
		} else {
			se.activeHandle.notificationLog = append(se.activeHandle.notificationLog, notification)
			if se.activeHandle.isWaitingForGDB {
				se.activeHandle.pendingNotifications = append(se.activeHandle.pendingNotifications, notification)
				if class, ok := notification["class"].(string); ok && class == "stopped" {
					select {
					case se.activeHandle.gdbNotifications <- notification:
					default:
						log.Logf(0, "gdb notification channel is full, dropping notification")
					}
				}
			} else if class, ok := notification["class"].(string); ok && class == "stopped" {
				fmt.Println("--- Received 'stopped' notification outside of wait, continuing execution ---")
				needsContinue = true
			} else {
				fmt.Println("--- Received unexpected GDB notification ---")
			}
		}
		se.activeHandle.mu.Unlock()

		if needsContinue && gdbInst != nil {
			_, err := gdbInst.Send("exec-continue")
			if err != nil {
				fmt.Printf("--- Failed to automatically continue GDB: %v ---\n", err)
			}
		}
	}
	gdbInst, err = gdb.New(notificationHandler)
	if err != nil {
		return nil, fmt.Errorf("failed to create GDB instance: %w", err)
	}

	// 3. Start the VM.
	handle, err := se.prepareVM(kernelCheckout, kernelBZImage, gdbSocket)
	if err != nil {
		gdbInst.Exit()
		return nil, fmt.Errorf("failed to prepare VM: %w", err)
	}

	// 4. Connect GDB to the socket and load symbols.
	log.Logf(0, "GDB is preparing to connect to the VM...")
	result, err := gdbInst.Send("target-select", "remote", gdbSocket)
	if err != nil {
		handle.Close()
		gdbInst.Exit()
		return nil, fmt.Errorf("failed to connect to GDB socket using 'target-select': %w", err)
	}
	jsonResult, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("--- 'target-select' Result ---\n%s\n----------------------------\n", string(jsonResult))
	log.Logf(0, "GDB connected to VM.")

	log.Logf(0, "GDB is loading the symbol file...")
	result, err = gdbInst.Send("file-symbol-file", handle.gdbInfo.VmlinuxPath)
	if err != nil {
		handle.Close()
		gdbInst.Exit()
		return nil, fmt.Errorf("failed to load symbol file with 'file-symbol-file': %w", err)
	}
	jsonResult, _ = json.MarshalIndent(result, "", "  ")
	fmt.Printf("--- 'file-symbol-file' Result ---\n%s\n-----------------------------\n", string(jsonResult))
	log.Logf(0, "GDB loaded symbol file.")

	log.Logf(0, "GDB is setting the environment directory...")
	result, err = gdbInst.Send("environment-directory", se.cfg.KernelDir)
	if err != nil {
		handle.Close()
		gdbInst.Exit()
		return nil, fmt.Errorf("failed to set environment directory: %w", err)
	}
	jsonResult, _ = json.MarshalIndent(result, "", "  ")
	fmt.Printf("--- 'environment-directory' Result ---\n%s\n----------------------------------\n", string(jsonResult))

	log.Logf(0, "GDB is setting the substitute path...")
	fromPath := "/syzkaller/managers/ci-upstream-bpf-kasan-gce/kernel"
	toPath := se.cfg.KernelDir
	result, err = gdbInst.Send("gdb-set", "substitute-path", fromPath, toPath)
	if err != nil {
		handle.Close()
		gdbInst.Exit()
		return nil, fmt.Errorf("failed to set substitute path: %w", err)
	}
	jsonResult, _ = json.MarshalIndent(result, "", "  ")
	fmt.Printf("--- 'gdb-set substitute-path' Result ---\n%s\n--------------------------------------\n", string(jsonResult))

	se.activeHandle = handle
	se.activeHandle.gdbInst = gdbInst
	se.activeHandle.gdbNotifications = gdbNotifications

	responseText := "The VM finished booting. It is now possible to use `gdb_command` or run a syzkaller program."
	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "open_vm_session",
			Response: map[string]any{"output": responseText},
		},
	}, nil
}

func (se *SyzExecutor) handleGdbCommand(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	logFunctionCall("gdb_command", fc)
	if se.activeHandle == nil || se.activeHandle.gdbInst == nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "gdb_command",
				Response: map[string]any{"error": "No active GDB session. Please use 'open_vm_session' first."},
			},
		}, nil
	}

	gdbCommand, ok := fc.Args["command"].(string)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'command' argument type")
	}

	se.activeHandle.mu.Lock()
	se.activeHandle.isCapturingForCmd = true
	se.activeHandle.cmdNotifications = nil
	se.activeHandle.mu.Unlock()

	result, err := se.activeHandle.gdbInst.Send("interpreter-exec", "console", gdbCommand)

	se.activeHandle.mu.Lock()
	se.activeHandle.isCapturingForCmd = false
	notifications := se.activeHandle.cmdNotifications
	se.activeHandle.mu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to execute GDB command '%s': %w", gdbCommand, err)
	}

	response := map[string]any{
		"result":        result,
		"notifications": notifications,
	}

	jsonOutput, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "gdb_command",
				Response: map[string]any{"output": fmt.Sprintf("failed to marshal gdb output: %v. Raw: %+v", err, response)},
			},
		}, nil
	}

	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "gdb_command",
			Response: map[string]any{"output": string(jsonOutput)},
		},
	}, nil
}

func (se *SyzExecutor) handleGdbLog(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	logFunctionCall("gdb_log", fc)
	if se.activeHandle == nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "gdb_log",
				Response: map[string]any{"error": "No active GDB session. Please use 'open_vm_session' first."},
			},
		}, nil
	}

	se.activeHandle.mu.Lock()
	log := se.activeHandle.notificationLog
	se.activeHandle.mu.Unlock()

	jsonOutput, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "gdb_log",
				Response: map[string]any{"output": fmt.Sprintf("failed to marshal notification log: %v", err)},
			},
		}, nil
	}
	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "gdb_log",
			Response: map[string]any{"log": string(jsonOutput)},
		},
	}, nil
}

func (se *SyzExecutor) handleRunSyzProgram(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	logFunctionCall("run_syz_program", fc)
	if se.activeHandle == nil || se.activeHandle.execInst == nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "run_syz_program",
				Response: map[string]any{"error": "No active VM session. Please use 'open_vm_session' first."},
			},
		}, nil
	}

	syzProgram, ok := fc.Args["syz_program"].(string)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'syz_program' argument type")
	}
	progFile, err := os.CreateTemp("", "syz-prog-*.syz")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp program file: %w", err)
	}
	defer os.Remove(progFile.Name())
	if _, err := progFile.WriteString(syzProgram); err != nil {
		return nil, fmt.Errorf("failed to write to temp program file: %w", err)
	}
	progFile.Close()

	reproOpts, err := parseReproOptions(progFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to parse repro options: %w", err)
	}
	csOpts := buildCsourceOptions(reproOpts)

	// Continue execution before running the program.
	fmt.Println("--- Resuming VM execution before running syz program ---")
	if _, err := se.activeHandle.gdbInst.Send("exec-continue"); err != nil {
		return nil, fmt.Errorf("failed to continue GDB before running program: %w", err)
	}

	go func() {
		result, err := se.activeHandle.execInst.RunSyzProgFile(progFile.Name(), 5*time.Minute, csOpts, instance.SyzExitConditions)
		if err != nil {
			fmt.Printf("\n--- Background syz program execution failed: %v ---\n", err)
			return
		}
		fmt.Printf("\n--- Background VM execution finished. ---\n")
		fmt.Printf("--- VM OUTPUT ---\n%s\n-----------------\n", result.Output)
		if result.Report != nil {
			fmt.Printf("\n--- CRASH DETECTED ---\nTitle: %s\n\n%s\n--------------------\n", result.Report.Title, result.Report.Report)
			fmt.Println("The VM has halted. You can now use 'gdb_command' to debug.")
		} else {
			fmt.Println("\n--- NO CRASH DETECTED (program finished) ---")
		}
	}()

	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "run_syz_program",
			Response: map[string]any{"output": "Syz program execution started in the background."},
		},
	}, nil
}

func (se *SyzExecutor) handleGdbSyzProgram(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	logFunctionCall("gdb_syz_program", fc)
	if se.activeHandle == nil || se.activeHandle.execInst == nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "gdb_syz_program",
				Response: map[string]any{"error": "No active VM session. Please use 'open_vm_session' first."},
			},
		}, nil
	}

	syzProgram, ok := fc.Args["syz_program"].(string)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'syz_program' argument type")
	}
	progFile, err := os.CreateTemp("", "syz-prog-*.syz")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp program file: %w", err)
	}
	defer os.Remove(progFile.Name())
	if _, err := progFile.WriteString(syzProgram); err != nil {
		return nil, fmt.Errorf("failed to write to temp program file: %w", err)
	}
	progFile.Close()

	reproOpts, err := parseReproOptions(progFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to parse repro options: %w", err)
	}
	csOpts := buildCsourceOptions(reproOpts)

	// Set up the wait condition
	se.activeHandle.mu.Lock()
	se.activeHandle.isWaitingForGDB = true
	se.activeHandle.pendingNotifications = nil // Clear previous notifications
	se.activeHandle.mu.Unlock()

	defer func() {
		se.activeHandle.mu.Lock()
		se.activeHandle.isWaitingForGDB = false
		se.activeHandle.pendingNotifications = nil
		se.activeHandle.mu.Unlock()
	}()

	// Run the program
	go func() {
		if _, err := se.activeHandle.gdbInst.Send("exec-continue"); err != nil {
			log.Logf(0, "failed to continue gdb in gdb_syz_program: %v", err)
			return
		}
		_, err := se.activeHandle.execInst.RunSyzProgFile(progFile.Name(), 5*time.Minute, csOpts, instance.SyzExitConditions)
		if err != nil {
			log.Logf(0, "syz program execution failed in gdb_syz_program: %v", err)
		}
	}()

	// Wait for the result
	fmt.Println("--- Waiting for GDB 'stopped' notification... ---")
	select {
	case <-se.activeHandle.gdbNotifications:
		fmt.Println("--- Received GDB 'stopped' notification. ---")
		se.activeHandle.mu.Lock()
		notifications := se.activeHandle.pendingNotifications
		se.activeHandle.mu.Unlock()

		jsonOutput, err := json.MarshalIndent(notifications, "", "  ")
		if err != nil {
			return &genai.Part{
				FunctionResponse: &genai.FunctionResponse{
					Name:     "gdb_syz_program",
					Response: map[string]any{"output": fmt.Sprintf("failed to marshal notifications: %v", err)},
				},
			}, nil
		}
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "gdb_syz_program",
				Response: map[string]any{"notifications": string(jsonOutput)},
			},
		}, nil
	case <-time.After(5 * time.Minute):
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name: "gdb_syz_program",
				Response: map[string]any{"error": "Timed out after 5 minutes of waiting for a GDB 'stopped' notification. " +
					"The program may not have hit a breakpoint or crashed."},
			},
		}, nil
	}
}

func (se *SyzExecutor) handleCloseVMSession(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	logFunctionCall("close_vm_session", fc)
	if se.activeHandle == nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name:     "close_vm_session",
				Response: map[string]any{"output": "No active VM session to close."},
			},
		}, nil
	}
	se.activeHandle.Close()
	se.activeHandle = nil
	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "close_vm_session",
			Response: map[string]any{"output": "VM session closed successfully."},
		},
	}, nil
}

// checkBuildStatus checks the build channel and updates the executor's state.
func (se *SyzExecutor) checkBuildStatus() {
	se.once.Do(func() {
		if se.cfg.BuildResultChan == nil {
			se.buildResult = &BuildResult{}
			return
		}
		fmt.Println("--- SyzExecutor: Waiting for build result... ---")
		result, ok := <-se.cfg.BuildResultChan
		if !ok {
			se.buildResult = &BuildResult{Err: fmt.Errorf("build channel was closed unexpectedly")}
			return
		}
		se.buildResult = result
		fmt.Println("--- SyzExecutor: Build result received. ---")
	})
}

func (se *SyzExecutor) getVmlinuxPath() (string, error) {
	se.checkBuildStatus()
	if se.cfg.BuildResultChan != nil && se.buildResult == nil {
		return "", fmt.Errorf("the kernel is still building. This tool requires the build to be complete")
	}
	if se.buildResult != nil && se.buildResult.Err != nil {
		return "", fmt.Errorf("cannot run because kernel build failed: %w", se.buildResult.Err)
	}
	vmlinuxPath := se.cfg.KernelCheckout
	if se.buildResult != nil && se.buildResult.VmlinuxPath != "" {
		vmlinuxPath = se.buildResult.VmlinuxPath
	}
	if vmlinuxPath == "" {
		return "", fmt.Errorf("vmlinux path is not available. Provide it via --kernel_checkout or build the kernel")
	}
	return vmlinuxPath, nil
}

func (se *SyzExecutor) handleObjdump(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	logFunctionCall("objdump", fc)
	vmlinuxPath, err := se.getVmlinuxPath()
	if err != nil {
		if strings.Contains(err.Error(), "still building") {
			return &genai.Part{
				FunctionResponse: &genai.FunctionResponse{
					Name:     "objdump",
					Response: map[string]any{"output": err.Error()},
				},
			}, nil
		}
		return nil, err
	}
	kernelObj, cleanup, err := HandleFileFlag(vmlinuxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get local kernel object directory: %w", err)
	}
	defer cleanup()
	symbolName, ok := fc.Args["symbol_name"].(string)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'symbol_name' argument type")
	}
	args := []string{
		"--source-comment=/*C*/",
		"--prefix=" + se.cfg.KernelDir,
		"--prefix-strip=4",
		"--no-show-raw-insn",
		"--no-addresses",
		"--line-numbers",
		"--section=.text",
		fmt.Sprintf("--disassemble=%s", symbolName), kernelObj,
	}
	cmd := exec.Command("objdump", args...)
	fmt.Printf("Executing command: %s\n", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("objdump command failed: %v\nOutput: %s", err, string(output))
	}
	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "objdump",
			Response: map[string]any{"output": string(output)},
		},
	}, nil
}

func (se *SyzExecutor) handlePahole(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	logFunctionCall("pahole", fc)
	vmlinuxPath, err := se.getVmlinuxPath()
	if err != nil {
		if strings.Contains(err.Error(), "still building") {
			return &genai.Part{
				FunctionResponse: &genai.FunctionResponse{
					Name:     "pahole",
					Response: map[string]any{"output": err.Error()},
				},
			}, nil
		}
		return nil, err
	}
	kernelObj, cleanup, err := HandleFileFlag(vmlinuxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get local kernel object directory: %w", err)
	}
	defer cleanup()
	name, ok := fc.Args["name"].(string)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'name' argument type")
	}
	args := []string{name, kernelObj}
	cmd := exec.Command("pahole", args...)
	fmt.Printf("Executing command: %s\n", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("pahole command failed: %v\nOutput: %s", err, string(output))
	}
	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "pahole",
			Response: map[string]any{"output": string(output)},
		},
	}, nil
}

// --- Merged Utility and VM Functions ---

const cacheDir = "/tmp/syz-run-cache"

type reproOpts map[string]interface{}

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

	vmlinuxPath := filepath.Join(localKernelObj, "vmlinux")
	gdbDetails := &gdbInfo{
		Socket:      gdbSocket,
		Command:     fmt.Sprintf("gdb %s -ex 'target remote %s'", vmlinuxPath, gdbSocket),
		VmlinuxPath: vmlinuxPath,
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

func getCacheKey(url string) string {
	hash := sha1.Sum([]byte(url))
	return hex.EncodeToString(hash[:])
}

func HandleFileFlag(path string) (localPath string, cleanup func(), err error) {
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		return path, func() {}, nil
	}

	cachePath := filepath.Join(cacheDir, getCacheKey(path))
	err = downloadAndDecompress(path, cachePath)
	return cachePath, func() {}, err
}

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
