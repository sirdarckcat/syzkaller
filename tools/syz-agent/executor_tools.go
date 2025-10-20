package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

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
	cfg         SyzExecutorConfig
	buildResult *BuildResult
	once        sync.Once
}

// NewSyzExecutor creates a new SyzExecutor.
func NewSyzExecutor(cfg SyzExecutorConfig) *SyzExecutor {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		log.Fatalf("failed to create cache directory: %v", err)
	}
	return &SyzExecutor{cfg: cfg}
}

// GetTools returns the set of tools for the SyzExecutor.
func (se *SyzExecutor) GetTools() []*Tool {
	return []*Tool{
		{
			Declaration: genai.FunctionDeclaration{
				Name: "run_syz_program",
				Description: "Executes a syzkaller program in a dedicated VM. " +
					"This is useful for reproducing a crash or testing a program. " +
					"The function returns the full VM output and a parsed crash report if one occurs.",
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
		},
	}
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

func (se *SyzExecutor) handleRunSyzProgram(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	se.checkBuildStatus()

	if se.cfg.BuildResultChan != nil && se.buildResult == nil {
		return &genai.Part{
			FunctionResponse: &genai.FunctionResponse{
				Name: "run_syz_program",
				Response: map[string]any{"output": "The kernel is still building in the background. " +
					"Please wait a few minutes and try calling this function again. " +
					"You can perform other tasks like code exploration in the meantime."},
			},
		}, nil
	}

	if se.buildResult != nil && se.buildResult.Err != nil {
		return nil, fmt.Errorf("cannot run syz program because kernel build failed: %w", se.buildResult.Err)
	}

	kernelCheckout := se.cfg.KernelCheckout
	kernelBZImage := se.cfg.KernelBZImage
	if se.buildResult != nil && se.buildResult.VmlinuxPath != "" {
		kernelCheckout = se.buildResult.VmlinuxPath
		kernelBZImage = se.buildResult.KernelImagePath
	}

	if kernelCheckout == "" || kernelBZImage == "" {
		return nil, fmt.Errorf("kernel checkout and kernel bzImage paths are not available to run the VM")
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

	result, gdbDetails, err := se.runProgram(progFile.Name(), kernelCheckout, kernelBZImage)
	if err != nil {
		return nil, fmt.Errorf("failed to run syz program: %w", err)
	}

	var responseText strings.Builder
	if gdbDetails != nil {
		responseText.WriteString(fmt.Sprintf("GDB server is available on a unix socket.\nTo connect: %s\n\n", gdbDetails.Command))
	}
	responseText.WriteString(fmt.Sprintf("--- VM OUTPUT ---\n%s\n-----------------\n", result.Output))
	if result.Report != nil {
		responseText.WriteString(fmt.Sprintf("\n--- CRASH REPORT ---\nTitle: %s\n\n%s\n--------------------\n", result.Report.Title, result.Report.Report))
	} else {
		responseText.WriteString("\n--- NO CRASH DETECTED ---\n")
	}

	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "run_syz_program",
			Response: map[string]any{"output": responseText.String()},
		},
	}, nil
}
