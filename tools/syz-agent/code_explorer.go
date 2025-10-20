package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"google.golang.org/genai"
)

const maxOutputSize = 500000 // Limit output to 500k characters

// CodeExplorer provides tools for exploring source code.
type CodeExplorer struct {
	kernelDir   string
	kernelObj   string
	fnProviders []FunctionProvider
}

// NewCodeExplorer creates a new CodeExplorer.
func NewCodeExplorer(kernelDir, kernelObj string) *CodeExplorer {
	return &CodeExplorer{kernelDir: kernelDir, kernelObj: kernelObj}
}

// GetTools returns the set of tools for code exploration.
func (ce *CodeExplorer) GetTools() []*Tool {
	return []*Tool{
		// {
		// 	Declaration: genai.FunctionDeclaration{
		// 		Name:        "git_grep",
		// 		Description: "Performs a text-based search for a string in the kernel source code using 'git grep'. This is useful for finding any mention of a function, variable, or string literal.",
		// 		Parameters: &genai.Schema{
		// 			Type: genai.TypeObject,
		// 			Properties: map[string]*genai.Schema{
		// 				"search_term": {Type: genai.TypeString, Description: "The text snippet to search for."},
		// 			},
		// 			Required: []string{"search_term"},
		// 		},
		// 	},
		// 	Handler: ce.handleGitGrep,
		// },
		{
			Declaration: genai.FunctionDeclaration{
				Name: "get_function_definition",
				Description: "Finds the definition of a C function in the kernel source code using Abstract Syntax Tree (AST) parsing. " +
					"This is more precise than text search for locating a function's body.",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"function_name": {Type: genai.TypeString, Description: "The name of the function to find."},
					},
					Required: []string{"function_name"},
				},
			},
			Handler: ce.handleGetFunctionDefinition,
		},
		{
			Declaration: genai.FunctionDeclaration{
				Name: "get_file_lines",
				Description: "Retrieves content from a specific file within the kernel source tree, limited to a " +
					"given line range. This is useful for inspecting specific parts of a file.",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"file_path": {
							Type:        genai.TypeString,
							Description: "The relative path to the file from the root of the kernel source tree.",
						},
						"start_line": {Type: genai.TypeInteger, Description: "The starting line number (1-based)."},
						"end_line":   {Type: genai.TypeInteger, Description: "The ending line number (inclusive)."},
					},
					Required: []string{"file_path", "start_line", "end_line"},
				},
			},
			Handler: ce.handleGetFileLines,
		},
	}
}

func (ce *CodeExplorer) handleGitGrep(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	searchTerm, ok := fc.Args["search_term"].(string)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'search_term' argument type")
	}
	output, err := ce.executeGitGrep(searchTerm)
	return ce.createResponse("git_grep", output, err), nil
}

func (ce *CodeExplorer) handleGetFunctionDefinition(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	functionName, ok := fc.Args["function_name"].(string)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'function_name' argument type")
	}
	output, err := ce.findFunctionDefinition(functionName)
	return ce.createResponse("get_function_definition", output, err), nil
}

func (ce *CodeExplorer) handleGetFileLines(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	filePath, ok := fc.Args["file_path"].(string)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'file_path' argument type")
	}
	// JSON numbers are float64 by default, so we need to cast them.
	startLine, ok := fc.Args["start_line"].(float64)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'start_line' argument type")
	}
	endLine, ok := fc.Args["end_line"].(float64)
	if !ok {
		return nil, fmt.Errorf("agent provided invalid 'end_line' argument type")
	}
	output, err := ce.executeGetFileLines(filePath, int(startLine), int(endLine))
	return ce.createResponse("get_file_lines", output, err), nil
}

func (ce *CodeExplorer) createResponse(name, output string, err error) *genai.Part {
	response := map[string]any{}
	if err != nil {
		response["error"] = err.Error()
	} else {
		response["output"] = truncateString(output, maxOutputSize)
	}
	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     name,
			Response: response,
		},
	}
}

func (ce *CodeExplorer) executeGitGrep(searchTerm string) (string, error) {
	cmd := exec.Command("git", "grep", "-W", "-p", "--break", "--heading", searchTerm, ".")
	cmd.Dir = ce.kernelDir
	fmt.Printf("Executing command: %s\n", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "No matches found.", nil
		}
		return "", fmt.Errorf("git grep command failed: %v\nOutput: %s", err, string(output))
	}
	return string(output), nil
}

func (ce *CodeExplorer) findFunctionDefinition(functionName string) (string, error) {
	if ce.fnProviders == nil {
		ce.fnProviders = []FunctionProvider{
			&GoELFProvider{kernelObj: ce.kernelObj, kernelDir: ce.kernelDir},
			&WeggliProvider{kernelDir: ce.kernelDir},
			&AstGrepProvider{kernelDir: ce.kernelDir},
		}
	}

	var lastErr error
	for _, p := range ce.fnProviders {
		// The Go provider needs the kernel object path.
		if _, ok := p.(*GoELFProvider); ok && ce.kernelObj == "" {
			fmt.Fprintln(os.Stderr, "skipping GoELFProvider: kernel object path not set")
			continue
		}
		output, err := p.FindFunctionDefinition(functionName)
		if err == nil {
			return output, nil
		}
		lastErr = err
		fmt.Fprintf(os.Stderr, "provider failed: %v\n", err)
	}
	return "", fmt.Errorf("all function definition providers failed; last error: %w", lastErr)
}

func (ce *CodeExplorer) executeGetFileLines(filePath string, startLine, endLine int) (string, error) {
	if startLine <= 0 || endLine < startLine {
		return "", fmt.Errorf("invalid line range: start %d, end %d", startLine, endLine)
	}

	fullPath := filepath.Join(ce.kernelDir, filePath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", fullPath, err)
	}

	lines := strings.Split(string(content), "\n")
	if startLine > len(lines) {
		return "", fmt.Errorf("start line %d is after end of file (%d lines)", startLine, len(lines))
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}

	return strings.Join(lines[startLine-1:endLine], "\n"), nil
}

func truncateString(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n... (output truncated)"
	}
	return s
}
