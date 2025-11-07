package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/genai"
)

// --- Core Tool Structures ---

const maxOutputSize = 500000 // Limit output to 500k characters

// ToolHandler defines the function signature for handling a tool's function call.
type ToolHandler func(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error)

// Tool represents a single function that the agent can call.
type Tool struct {
	Declaration genai.FunctionDeclaration
	Handler     ToolHandler
	Classes     []string // The agent classes this tool belongs to.
}

// ToolProvider is an interface for components that provide tools to the agent.
type ToolProvider interface {
	GetTools() []*Tool
}

// ToolSet manages the collection of available tools.
type ToolSet struct {
	tools map[string]*Tool
}

// NewToolSet creates a new ToolSet from a list of providers.
func NewToolSet(providers ...ToolProvider) *ToolSet {
	ts := &ToolSet{
		tools: make(map[string]*Tool),
	}
	for _, p := range providers {
		for _, t := range p.GetTools() {
			ts.tools[t.Declaration.Name] = t
		}
	}
	return ts
}

// GetToolConfig returns a genai.Tool configuration for all available tools.
func (ts *ToolSet) GetToolConfig() *genai.Tool {
	var declarations []*genai.FunctionDeclaration
	for _, t := range ts.tools {
		declarations = append(declarations, &t.Declaration)
	}
	return &genai.Tool{FunctionDeclarations: declarations}
}

// GetToolConfigForClass returns a genai.Tool configuration for a specific agent class.
func (ts *ToolSet) GetToolConfigForClass(class string) *genai.Tool {
	var declarations []*genai.FunctionDeclaration
	for _, t := range ts.tools {
		for _, c := range t.Classes {
			if c == class {
				declarations = append(declarations, &t.Declaration)
				break
			}
		}
	}
	return &genai.Tool{FunctionDeclarations: declarations}
}

// Handle dispatches a function call to the appropriate tool's handler and logs the interaction.
func (ts *ToolSet) Handle(agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	tool, ok := ts.tools[fc.Name]
	if !ok {
		return nil, fmt.Errorf("unknown tool function: %s", fc.Name)
	}

	logFunctionCall(fc.Name, fc)
	part, err := tool.Handler(ts, agentClass, fc)
	if err != nil {
		return nil, err
	}

	if part != nil && part.FunctionResponse != nil {
		if output, ok := part.FunctionResponse.Response["output"].(string); ok {
			printToolOutputPreview(fc.Name, output)
		}
	}

	return part, nil
}

// --- Tool Provider Implementation ---

// Tools provides a unified set of tools for the agent.
type Tools struct {
	kernelDir      string
	kernelObj      string
	report         string
	reproducer     string
	cscopeProvider *CscopeProvider
	weggliProvider *WeggliProvider
	executor       *Executor
}

// NewTools creates a new Tools provider.
func NewTools(kernelDir, kernelObj, report, reproducer string, cscopeProvider *CscopeProvider, weggliProvider *WeggliProvider, executor *Executor) *Tools {
	return &Tools{
		kernelDir:      kernelDir,
		kernelObj:      kernelObj,
		report:         report,
		reproducer:     reproducer,
		cscopeProvider: cscopeProvider,
		weggliProvider: weggliProvider,
		executor:       executor,
	}
}

// GetTools returns the combined set of all tools available to the agent.
func (at *Tools) GetTools() []*Tool {
	tools := []*Tool{
		{
			Declaration: genai.FunctionDeclaration{Name: "get_crash_context", Description: "Retrieves the crash report and syz-reproducer for the current bug.", Parameters: &genai.Schema{Type: genai.TypeObject}},
			Handler:     at.handleGetCrashContext,
			Classes:     []string{"crash_analyzer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "git_grep", Description: "Performs a text-based search for a string in the kernel source code.",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"search_term": {Type: genai.TypeString, Description: "The text snippet to search for."}}, Required: []string{"search_term"}},
			},
			Handler: at.handleGitGrep,
			Classes: []string{"code_explorer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "get_function_git_log", Description: "Retrieves the git log for a specific function within a file, showing its evolution.",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{
					"function_name": {Type: genai.TypeString, Description: "The name of the function."},
					"file_path":     {Type: genai.TypeString, Description: "The relative path to the file containing the function."},
				}, Required: []string{"function_name", "file_path"}},
			},
			Handler: at.handleGetFunctionGitLog,
			Classes: []string{"code_explorer", "crash_analyzer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "get_function_definition", Description: "Finds the definition of a C function in the kernel source code.",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"function_name": {Type: genai.TypeString, Description: "The name of the function to find."}}, Required: []string{"function_name"}},
			},
			Handler: at.handleGetFunctionDefinition,
			Classes: []string{"crash_analyzer", "code_explorer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "find_function_calls", Description: "Finds all call sites for a given C function in the kernel source code.",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"function_name": {Type: genai.TypeString, Description: "The name of the function to find calls for."}}, Required: []string{"function_name"}},
			},
			Handler: at.handleFindFunctionCalls,
			Classes: []string{"crash_analyzer", "code_explorer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "get_file_lines", Description: "Retrieves content from a specific file within the kernel source tree.",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{
					"file_path":  {Type: genai.TypeString, Description: "The relative path to the file."},
					"start_line": {Type: genai.TypeInteger, Description: "The starting line number (1-based)."},
					"end_line":   {Type: genai.TypeInteger, Description: "The ending line number (inclusive)."},
				}, Required: []string{"file_path", "start_line", "end_line"}},
			},
			Handler: at.handleGetFileLines,
			Classes: []string{"crash_analyzer", "code_explorer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "read_playbook", Description: "Reads a section from the agent's analysis playbook. If 'section' is empty, it returns the index.",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{
					"section": {Type: genai.TypeString, Description: "The name of the section file to read (e.g., '1_initial_triage.md')."},
				}},
			},
			Handler: at.handleReadPlaybook,
			Classes: []string{"crash_analyzer", "code_explorer", "executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "find_struct_allocations", Description: "Finds allocations of a given C structure variable in the kernel source code. Example: struct my_struct *var; var = kmalloc(...);",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"struct_name": {Type: genai.TypeString, Description: "The name of the structure to find allocations for."}}, Required: []string{"struct_name"}},
			},
			Handler: at.handleFindStructAllocations,
			Classes: []string{"code_explorer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "find_field_allocations", Description: "Finds allocations assigned to a specific struct field. Example: some_struct->field = kmalloc(...);",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"field_name": {Type: genai.TypeString, Description: "The name of the struct field being allocated."}}, Required: []string{"field_name"}},
			},
			Handler: at.handleFindFieldAllocations,
			Classes: []string{"code_explorer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "find_struct_frees", Description: "Finds frees of a pointer variable of a given struct type. Example: struct my_struct *var; kfree(var);",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"struct_name": {Type: genai.TypeString, Description: "The name of the struct type for the pointer being freed."}}, Required: []string{"struct_name"}},
			},
			Handler: at.handleFindStructFrees,
			Classes: []string{"code_explorer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "find_field_frees", Description: "Finds frees of a specific struct field. Example: kfree(some_struct->field);",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"field_name": {Type: genai.TypeString, Description: "The name of the struct field being freed."}}, Required: []string{"field_name"}},
			},
			Handler: at.handleFindFieldFrees,
			Classes: []string{"code_explorer"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "pahole", Description: "Inspects a kernel data structure's layout using 'pahole'.",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"name": {Type: genai.TypeString, Description: "The name of the class or struct to inspect."}}, Required: []string{"name"}},
			},
			Handler: at.handlePahole,
			Classes: []string{"crash_analyzer", "code_explorer", "executor"},
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "objdump", Description: "Gets the interleaved C source and assembly for a function or symbol.",
				Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{"symbol_name": {Type: genai.TypeString, Description: "The name of the function or symbol to disassemble."}}, Required: []string{"symbol_name"}},
			},
			Handler: at.handleObjdump,
			Classes: []string{"code_explorer", "executor"},
		},
	}

	if at.executor != nil {
		executorTools := []*Tool{
			{
				Declaration: genai.FunctionDeclaration{Name: "open_vm_session", Description: "Starts a new VM and connects a GDB server to it.", Parameters: &genai.Schema{Type: genai.TypeObject}},
				Handler:     at.handleOpenVMSession,
				Classes:     []string{"executor"},
			},
			{
				Declaration: genai.FunctionDeclaration{
					Name: "run_syz_program", Description: "Executes a syzkaller program in the currently running VM.",
					Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{
						"syz_program":     {Type: genai.TypeString, Description: "The full content of the .syz syzkaller program to execute."},
						"timeout_seconds": {Type: genai.TypeInteger, Description: "Optional. The timeout in seconds to run the program for. Defaults to 300."},
					}, Required: []string{"syz_program"}},
				},
				Handler: at.handleRunSyzProgram,
				Classes: []string{"executor"},
			},
			{
				Declaration: genai.FunctionDeclaration{
					Name: "gdb_syz_program", Description: "Executes a syzkaller program and waits for a GDB breakpoint or crash.",
					Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{
						"syz_program":     {Type: genai.TypeString, Description: "The full content of the .syz syzkaller program to execute."},
						"timeout_seconds": {Type: genai.TypeInteger, Description: "Optional. The timeout in seconds to wait for a GDB event. Defaults to 120."},
					}, Required: []string{"syz_program"}},
				},
				Handler: at.handleGdbSyzProgram,
				Classes: []string{"executor"},
			},
			{
				Declaration: genai.FunctionDeclaration{
					Name: "gdb_command", Description: "Executes a command in the active GDB session.",
					Parameters: &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{
						"command":         {Type: genai.TypeString, Description: "The GDB console command to execute."},
						"timeout_seconds": {Type: genai.TypeInteger, Description: "Optional. The timeout in seconds for the command. Defaults to 60."},
					}, Required: []string{"command"}},
				},
				Handler: at.handleGdbCommand,
				Classes: []string{"executor"},
			},
			{
				Declaration: genai.FunctionDeclaration{Name: "gdb_log", Description: "Returns the log of all GDB notifications received.", Parameters: &genai.Schema{Type: genai.TypeObject}},
				Handler:     at.handleGdbLog,
				Classes:     []string{"executor"},
			},
			{
				Declaration: genai.FunctionDeclaration{Name: "close_vm_session", Description: "Closes the currently running VM and its associated GDB session.", Parameters: &genai.Schema{Type: genai.TypeObject}},
				Handler:     at.handleCloseVMSession,
				Classes:     []string{"executor"},
			},
		}
		tools = append(tools, executorTools...)
	}
	return tools
}

func (at *Tools) createResponse(name, output string, err error) *genai.Part {
	response := map[string]any{}
	if err != nil {
		response["error"] = err.Error()
	} else {
		response["output"] = truncateString(output, maxOutputSize)
	}
	return &genai.Part{FunctionResponse: &genai.FunctionResponse{Name: name, Response: response}}
}

// --- Tool Handlers ---

func (at *Tools) handleGetCrashContext(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	contextText := fmt.Sprintf("--- Crash Report ---\n%s\n\n--- Syz-Reproducer ---\n%s", at.report, at.reproducer)
	return at.createResponse("get_crash_context", contextText, nil), nil
}

func (at *Tools) handleGitGrep(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	searchTerm, _ := fc.Args["search_term"].(string)
	output, err := at.executeGitGrep(searchTerm)
	return at.createResponse("git_grep", output, err), nil
}

func (at *Tools) handleGetFunctionGitLog(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	functionName, _ := fc.Args["function_name"].(string)
	filePath, _ := fc.Args["file_path"].(string)
	output, err := at.executeGetFunctionGitLog(functionName, filePath)
	return at.createResponse("get_function_git_log", output, err), nil
}

func (at *Tools) handleGetFunctionDefinition(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	functionName, _ := fc.Args["function_name"].(string)
	output, err := at.cscopeProvider.FindFunctionDefinition(functionName)
	return at.createResponse("get_function_definition", output, err), nil
}

func (at *Tools) handleFindFunctionCalls(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	functionName, _ := fc.Args["function_name"].(string)
	output, err := at.cscopeProvider.FindFunctionCalls(functionName)
	return at.createResponse("find_function_calls", output, err), nil
}

func (at *Tools) handleReadPlaybook(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	if agentClass == "" {
		return nil, fmt.Errorf("read_playbook can only be used by a specific agent class")
	}
	section, _ := fc.Args["section"].(string)
	output, err := at.executeReadPlaybook(agentClass, section)
	return at.createResponse("read_playbook", output, err), nil
}

func (at *Tools) handleFindStructAllocations(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	structName, _ := fc.Args["struct_name"].(string)
	output, err := at.weggliProvider.FindStructAllocations(structName)
	return at.createResponse("find_struct_allocations", output, err), nil
}

func (at *Tools) handleFindFieldAllocations(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	fieldName, _ := fc.Args["field_name"].(string)
	output, err := at.weggliProvider.FindFieldAllocations(fieldName)
	return at.createResponse("find_field_allocations", output, err), nil
}

func (at *Tools) handleFindStructFrees(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	structName, _ := fc.Args["struct_name"].(string)
	output, err := at.weggliProvider.FindStructFrees(structName)
	return at.createResponse("find_struct_frees", output, err), nil
}

func (at *Tools) handleFindFieldFrees(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	fieldName, _ := fc.Args["field_name"].(string)
	output, err := at.weggliProvider.FindFieldFrees(fieldName)
	return at.createResponse("find_field_frees", output, err), nil
}

func (at *Tools) handleGetFileLines(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	filePath, _ := fc.Args["file_path"].(string)
	startLine, _ := fc.Args["start_line"].(float64)
	endLine, _ := fc.Args["end_line"].(float64)
	output, err := at.executeGetFileLines(filePath, int(startLine), int(endLine))
	return at.createResponse("get_file_lines", output, err), nil
}

func (at *Tools) handlePahole(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	name, _ := fc.Args["name"].(string)
	output, err := at.executePahole(name)
	return at.createResponse("pahole", output, err), nil
}

func (at *Tools) handleObjdump(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	symbolName, _ := fc.Args["symbol_name"].(string)
	output, err := at.executeObjdump(symbolName)
	return at.createResponse("objdump", output, err), nil
}

func (at *Tools) handleOpenVMSession(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	output, err := at.executor.OpenVMSession()
	return at.createResponse("open_vm_session", output, err), nil
}

func (at *Tools) handleRunSyzProgram(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	syzProgram, _ := fc.Args["syz_program"].(string)
	timeoutSec, ok := fc.Args["timeout_seconds"].(float64)
	if !ok {
		timeoutSec = 300 // Default
	}
	output, err := at.executor.RunSyzProgram(syzProgram, time.Duration(timeoutSec)*time.Second)
	return at.createResponse("run_syz_program", output, err), nil
}

func (at *Tools) handleGdbSyzProgram(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	syzProgram, _ := fc.Args["syz_program"].(string)
	timeoutSec, ok := fc.Args["timeout_seconds"].(float64)
	if !ok {
		timeoutSec = 120 // Default
	}
	output, err := at.executor.GdbSyzProgram(syzProgram, time.Duration(timeoutSec)*time.Second)
	return at.createResponse("gdb_syz_program", output, err), nil
}

func (at *Tools) handleGdbCommand(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	command, _ := fc.Args["command"].(string)
	timeoutSec, ok := fc.Args["timeout_seconds"].(float64)
	if !ok {
		timeoutSec = 60 // Default
	}
	output, err := at.executor.GdbCommand(command, time.Duration(timeoutSec)*time.Second)
	return at.createResponse("gdb_command", output, err), nil
}

func (at *Tools) handleGdbLog(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	output, err := at.executor.GdbLog()
	response := map[string]any{}
	if err != nil {
		response["error"] = err.Error()
	} else {
		response["log"] = output // gdb_log has a different response structure
	}
	return &genai.Part{FunctionResponse: &genai.FunctionResponse{Name: "gdb_log", Response: response}}, nil
}

func (at *Tools) handleCloseVMSession(ts *ToolSet, agentClass string, fc *genai.FunctionCall) (*genai.Part, error) {
	output, err := at.executor.CloseVMSession()
	return at.createResponse("close_vm_session", output, err), nil
}

// --- Execution Helpers ---

func (at *Tools) executeGitGrep(searchTerm string) (string, error) {
	cmd := exec.Command("git", "grep", "-W", "-p", "--break", "--heading", searchTerm, ".")
	cmd.Dir = at.kernelDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "No matches found.", nil
		}
		return "", fmt.Errorf("git grep command failed: %v\nOutput: %s", err, string(output))
	}
	return string(output), nil
}

func (at *Tools) executeGetFunctionGitLog(functionName, filePath string) (string, error) {
	lArg := fmt.Sprintf(":%s:%s", functionName, filePath)
	cmd := exec.Command("git", "log", "-L", lArg)
	cmd.Dir = at.kernelDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git log -L command failed: %v\nOutput: %s", err, string(output))
	}
	if len(strings.TrimSpace(string(output))) == 0 {
		return fmt.Sprintf("No git log found for function '%s' in file '%s'.", functionName, filePath), nil
	}
	return string(output), nil
}

func (at *Tools) executeReadPlaybook(agentClass, section string) (string, error) {
	playbookDir := filepath.Join("docs", "agent", agentClass)
	if _, err := os.Stat(playbookDir); os.IsNotExist(err) {
		return "", fmt.Errorf("no playbook found for agent class '%s'", agentClass)
	}

	// If no section is specified, read the index file (README.md).
	if section == "" {
		readmePath := filepath.Join(playbookDir, "README.md")
		content, err := os.ReadFile(readmePath)
		if err != nil {
			return "", fmt.Errorf("failed to read playbook index for '%s': %w", agentClass, err)
		}
		return string(content), nil
	}

	// A section was specified, try to read it.
	sectionPath := filepath.Join(playbookDir, section)
	content, err := os.ReadFile(sectionPath)
	if err == nil {
		return string(content), nil
	}

	// If the section file doesn't exist, fall back to the index with a warning.
	if os.IsNotExist(err) {
		warningMsg := fmt.Sprintf("Warning: Section '%s' not found. Returning the playbook index instead.\n\n", section)
		readmePath := filepath.Join(playbookDir, "README.md")
		readmeContent, readmeErr := os.ReadFile(readmePath)
		if readmeErr != nil {
			return "", fmt.Errorf("section '%s' not found and failed to read playbook index as fallback: %w", section, readmeErr)
		}
		return warningMsg + string(readmeContent), nil
	}

	// For any other type of error, return it directly.
	return "", fmt.Errorf("failed to read playbook section '%s': %w", section, err)
}

func (at *Tools) executePahole(name string) (string, error) {
	if at.kernelObj == "" {
		return "", fmt.Errorf("vmlinux path is not available, cannot run pahole. Please specify --kernel_checkout or use --build-kernel")
	}
	kernelObj, cleanup, err := HandleFileFlag(at.kernelObj)
	if err != nil {
		return "", fmt.Errorf("failed to get local kernel object directory: %w", err)
	}
	defer cleanup()
	cmd := exec.Command("pahole", "-C", name, kernelObj)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pahole command failed: %v\nOutput: %s", err, string(output))
	}
	return string(output), nil
}

func (at *Tools) executeObjdump(symbolName string) (string, error) {
	if at.kernelObj == "" {
		return "", fmt.Errorf("vmlinux path is not available, cannot run objdump. Please specify --kernel_checkout or use --build-kernel")
	}
	kernelObj, cleanup, err := HandleFileFlag(at.kernelObj)
	if err != nil {
		return "", fmt.Errorf("failed to get local kernel object directory: %w", err)
	}
	defer cleanup()
	args := []string{
		"--source-comment=/*C*/", "--prefix=" + at.kernelDir, "--prefix-strip=4",
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

func (at *Tools) executeGetFileLines(filePath string, startLine, endLine int) (string, error) {
	if startLine <= 0 || endLine < startLine {
		return "", fmt.Errorf("invalid line range")
	}
	fullPath := filepath.Join(at.kernelDir, filePath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", fullPath, err)
	}
	lines := strings.Split(string(content), "\n")
	if startLine > len(lines) {
		return "", fmt.Errorf("start line is after end of file")
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}
	var result strings.Builder
	result.WriteString(filePath + "\n")
	for i := startLine - 1; i < endLine; i++ {
		result.WriteString(fmt.Sprintf("%d | %s\n", i+1, lines[i]))
	}
	return result.String(), nil
}

func truncateString(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n... (output truncated)"
	}
	return s
}

// --- Tool Initialization ---

// initializeTools creates and configures all the tool providers for the agent.
func initializeTools(kernelDir, crashReport, syzReproducer string, cscopeProvider *CscopeProvider, weggliProvider *WeggliProvider, buildResultChan chan *BuildResult) *ToolSet {
	kernelObj := *flagKernelCheckout
	if buildResultChan != nil {
		res := <-buildResultChan
		if res.Err != nil {
			fmt.Printf("Warning: kernel build failed. Executor tools may not function correctly: %v\n", res.Err)
		} else if res.VmlinuxPath != "" {
			kernelObj = res.VmlinuxPath
		}
	}

	var executor *Executor
	if (*flagKernelCheckout != "" && *flagKernelBZImage != "") || *flagBuildKernel {
		fmt.Println("Executor enabled.")
		syzkallerPath, err := os.Getwd()
		if err != nil {
			fmt.Printf("Critical: failed to get current working directory for Executor: %v\n", err)
		} else {
			executor = NewExecutor(ExecutorConfig{
				SyzkallerPath:   syzkallerPath,
				KernelDir:       kernelDir,
				KernelCheckout:  *flagKernelCheckout,
				DiskImage:       *flagDiskImage,
				KernelBZImage:   *flagKernelBZImage,
				Debug:           *flagDebug,
				BuildResultChan: buildResultChan,
			})
		}
	} else {
		fmt.Println("Executor disabled (kernel artifacts not provided and --build-kernel=false).")
	}

	toolProvider := NewTools(kernelDir, kernelObj, crashReport, syzReproducer, cscopeProvider, weggliProvider, executor)
	return NewToolSet(toolProvider)
}
