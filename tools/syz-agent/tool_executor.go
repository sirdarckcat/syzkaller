package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cyrus-and/gdb"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
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
				Description: "Executes a syzkaller program in the currently running VM. " +
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
			Classes: []string{"syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name:        "gdb_syz_program",
				Description: "Executes a syzkaller program (defines syzkalls to run) in the currently running VM and waits for a GDB breakpoint or crash, returning all GDB notifications.",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"syz_program": {
							Type:        genai.TypeString,
							Description: "The full content of the .syz syzkaller program to execute (using the Syzkaller fuzzer DSL).",
						},
					},
					Required: []string{"syz_program"},
				},
			},
			Handler: se.handleGdbSyzProgram,
			Classes: []string{"syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "gdb_command",
				Description: "Executes a command in the active GDB session using the MI 'interpreter-exec' command. " +
					"A session must be started with 'open_vm_session'. Key commands include 'continue', 'bt', 'info registers', 'break'.",
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
			Classes: []string{"syzkaller_executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name:        "gdb_log",
				Description: "Returns the log of all GDB notifications received during the current session.",
				Parameters:  &genai.Schema{Type: genai.TypeObject},
			},
			Handler: se.handleGdbLog,
			Classes: []string{"syzkaller_executor"},
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
			Classes: []string{"code_explorer", "syzkaller_executor"},
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
