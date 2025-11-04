package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// --- WeggliProvider ---

// WeggliProvider uses weggli to find code patterns.
type WeggliProvider struct {
	kernelDir string
}

// executeWeggliCommand provides a generic way to run weggli with a pattern and replacements.
func (p *WeggliProvider) executeWeggliCommand(pattern string, replacements map[string]string, notFoundMsg string) (string, error) {
	args := []string{"--after=9999999"}
	for key, value := range replacements {
		args = append(args, "-R", fmt.Sprintf("%s=%s", key, value))
	}
	args = append(args, pattern, p.kernelDir)

	cmd := exec.Command("weggli", args...)
	cmd.Dir = p.kernelDir
	output, err := cmd.CombinedOutput()

	if err != nil {
		// weggli exits with 1 if no matches are found.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return notFoundMsg, nil
		}
		return "", fmt.Errorf("weggli command failed: %w\nOutput: %s", err, string(output))
	}
	if len(strings.TrimSpace(string(output))) == 0 {
		return notFoundMsg, nil
	}
	return string(output), nil
}

func (p *WeggliProvider) FindStructAllocations(structName string) (string, error) {
	pattern := `_ $function(){struct $type *$var;$var=$alloc();}`
	replacements := map[string]string{
		"alloc": "^k.+alloc",
		"type":  structName,
	}
	notFoundMsg := fmt.Sprintf("No allocations found for struct '%s'.", structName)
	return p.executeWeggliCommand(pattern, replacements, notFoundMsg)
}

func (p *WeggliProvider) FindFieldAllocations(fieldName string) (string, error) {
	pattern := `_ $fn() { ...; _->_.$field = $alloc(_); ...}`
	replacements := map[string]string{
		"alloc": "^k.+alloc",
		"field": fieldName,
	}
	notFoundMsg := fmt.Sprintf("No allocations found for field '%s'.", fieldName)
	return p.executeWeggliCommand(pattern, replacements, notFoundMsg)
}

func (p *WeggliProvider) FindStructFrees(structName string) (string, error) {
	pattern := `_ $fn() { struct $type * $var; ...; kfree($var); }`
	replacements := map[string]string{"type": structName}
	notFoundMsg := fmt.Sprintf("No frees found for variables of type 'struct %s'.", structName)
	return p.executeWeggliCommand(pattern, replacements, notFoundMsg)
}

func (p *WeggliProvider) FindFieldFrees(fieldName string) (string, error) {
	pattern := `_ $fn() { ...; $free(_->$field); ...}`
	replacements := map[string]string{
		"free":  "kfree",
		"field": fieldName,
	}
	notFoundMsg := fmt.Sprintf("No frees found for field '%s'.", fieldName)
	return p.executeWeggliCommand(pattern, replacements, notFoundMsg)
}

// --- CscopeProvider ---

// CscopeProvider uses cscope to find function definitions and calls.
type CscopeProvider struct {
	kernelDir string
}

// NewCscopeProvider creates a new CscopeProvider and builds the cscope database.
func NewCscopeProvider(kernelDir string) (*CscopeProvider, error) {
	fmt.Println("--- Building cscope database... ---")
	cmd := exec.Command("cscope", "-b", "-q", "-k", "-R")
	cmd.Dir = kernelDir
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cscope database build failed: %w\nOutput: %s", err, string(output))
	}
	fmt.Println("--- cscope database built successfully. ---")
	return &CscopeProvider{kernelDir: kernelDir}, nil
}

// FindFunctionDefinition finds a function's source code using the cscope tool.
// It processes all results returned by cscope.
func (p *CscopeProvider) FindFunctionDefinition(functionName string) (string, error) {
	cmd := exec.Command("cscope", "-d", "-L1", functionName)
	cmd.Dir = p.kernelDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cscope definition query failed: %w\nOutput: %s", err, string(output))
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	var allDefinitions []string
	var foundResults bool

	for scanner.Scan() {
		foundResults = true
		line := scanner.Text()

		parts := strings.SplitN(line, " ", 4)
		if len(parts) < 3 {
			// Skip malformed lines, but log them.
			fmt.Fprintf(os.Stderr, "warning: failed to parse cscope output line: %s\n", line)
			continue
		}
		filePath := parts[0]
		startLineNum, err := strconv.Atoi(parts[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse line number from cscope: %s\n", line)
			continue
		}

		fullPath := filepath.Join(p.kernelDir, filePath)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to read source file %s: %v\n", fullPath, err)
			continue
		}

		lines := strings.Split(string(content), "\n")
		if startLineNum > len(lines) {
			fmt.Fprintf(os.Stderr, "warning: cscope line number %d is out of bounds for %s\n", startLineNum, filePath)
			continue
		}

		endLineNum := -1
		braceCount := 0
		inFunction := false
		for i := startLineNum - 1; i < len(lines); i++ {
			if strings.Contains(lines[i], "{") {
				braceCount++
				inFunction = true
			}
			if strings.Contains(lines[i], "}") {
				braceCount--
			}
			if inFunction && braceCount == 0 {
				endLineNum = i + 1
				break
			}
		}
		if endLineNum == -1 {
			endLineNum = len(lines) // Fallback if closing brace isn't found
		}

		allDefinitions = append(allDefinitions, strings.Join(lines[startLineNum-1:endLineNum], "\n"))
	}

	if !foundResults {
		return "", fmt.Errorf("cscope found no definition for function '%s'", functionName)
	}

	return strings.Join(allDefinitions, "\n\n---\n\n"), nil
}

// FindFunctionCalls finds all call sites for a function using cscope.
func (p *CscopeProvider) FindFunctionCalls(functionName string) (string, error) {
	cmd := exec.Command("cscope", "-d", "-L3", functionName)
	cmd.Dir = p.kernelDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cscope call query failed: %w\nOutput: %s", err, string(output))
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return "", fmt.Errorf("cscope found no calls for function '%s'", functionName)
	}
	return string(output), nil
}
