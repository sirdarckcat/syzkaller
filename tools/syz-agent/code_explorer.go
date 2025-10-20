package main

import (
	"fmt"
	"os/exec"
	"strings"

	"google.golang.org/genai"
)

const maxOutputSize = 500000 // Limit output to 500k characters

// CodeExplorer provides tools for exploring source code.
type CodeExplorer struct {
	kernelDir string
}

// NewCodeExplorer creates a new CodeExplorer.
func NewCodeExplorer(kernelDir string) *CodeExplorer {
	return &CodeExplorer{kernelDir: kernelDir}
}

// GetTools returns the set of tools for code exploration.
func (ce *CodeExplorer) GetTools() []*Tool {
	return []*Tool{
		{
			Declaration: genai.FunctionDeclaration{
				Name:        "git_grep",
				Description: "Performs a text-based search for a string in the kernel source code using 'git grep'. This is useful for finding any mention of a function, variable, or string literal.",
				Parameters: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"search_term": {Type: genai.TypeString, Description: "The text snippet to search for."},
					},
					Required: []string{"search_term"},
				},
			},
			Handler: ce.handleGitGrep,
		},
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
	// Step 1: Try the fast path with weggli.
	weggliPattern := fmt.Sprintf("_ %s(){}", functionName)
	cmdWeggli := exec.Command("weggli", weggliPattern, ".")
	cmdWeggli.Dir = ce.kernelDir
	fmt.Printf("Executing command (fast attempt): %s\n", cmdWeggli.String())
	outputWeggli, errWeggli := cmdWeggli.CombinedOutput()

	if errWeggli == nil && len(strings.TrimSpace(string(outputWeggli))) > 0 {
		fmt.Println("weggli found a match.")
		return string(outputWeggli), nil
	}
	if errWeggli != nil {
		fmt.Printf("weggli failed, but continuing to ast-grep. Error: %v\n", errWeggli)
	} else {
		fmt.Println("weggli found no matches. Falling back to ast-grep for a more thorough search.")
	}

	// Step 2: If weggli fails or finds nothing, fall back to the slower but more robust ast-grep.
	astGrepPattern := fmt.Sprintf("$$$ %s($$$ARGS){$$$}", functionName)
	cmdAstGrep := exec.Command("ast-grep", "run", "--lang=c", "--pattern", astGrepPattern, "--selector", "function_definition", ".")
	cmdAstGrep.Dir = ce.kernelDir
	fmt.Printf("Executing command (fallback): %s\n", cmdAstGrep.String())
	outputAstGrep, errAstGrep := cmdAstGrep.CombinedOutput()
	if errAstGrep != nil {
		if exitErr, ok := errAstGrep.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "No definition found for that function.", nil
		}
		return "", fmt.Errorf("ast-grep command failed: %v\nOutput: %s", errAstGrep, string(outputAstGrep))
	}
	return string(outputAstGrep), nil
}

func truncateString(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n... (output truncated)"
	}
	return s
}
