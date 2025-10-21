package main

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FunctionProvider defines an interface for finding function source code.
type FunctionProvider interface {
	// FindFunctionDefinition attempts to find the source code for a given function.
	FindFunctionDefinition(functionName string) (string, error)
}

// --- GoELFProvider ---

// GoELFProvider uses ELF and DWARF info to find function definitions.
type GoELFProvider struct {
	kernelObj string
	kernelDir string
}

// FindFunctionDefinition finds a function's source code using ELF and DWARF debugging information.
func (p *GoELFProvider) FindFunctionDefinition(functionName string) (string, error) {
	kernelObj, cleanup, err := HandleFileFlag(p.kernelObj)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for kernel object: %w", err)
	}
	defer cleanup()

	file, err := elf.Open(kernelObj)
	if err != nil {
		return "", fmt.Errorf("failed to open kernel object: %w", err)
	}
	defer file.Close()

	symbols, err := file.Symbols()
	if err != nil {
		return "", fmt.Errorf("failed to read ELF symbols: %w", err)
	}
	var fnSymbol *elf.Symbol
	for i := range symbols {
		if symbols[i].Name == functionName {
			fnSymbol = &symbols[i]
			break
		}
	}
	if fnSymbol == nil {
		return "", fmt.Errorf("ELF symbol for %s not found", functionName)
	}

	d, err := file.DWARF()
	if err != nil {
		return "", fmt.Errorf("failed to read DWARF info: %w", err)
	}

	r := d.Reader()
	for {
		entry, err := r.Next()
		if err == io.EOF || entry == nil {
			break
		}
		if err != nil {
			return "", fmt.Errorf("error reading DWARF entry: %w", err)
		}
		if entry.Tag != dwarf.TagCompileUnit {
			r.SkipChildren()
			continue
		}

		ranges, err := d.Ranges(entry)
		if err != nil {
			continue
		}
		unitContainsFunc := false
		for _, r := range ranges {
			if fnSymbol.Value >= r[0] && fnSymbol.Value < r[1] {
				unitContainsFunc = true
				break
			}
		}
		if !unitContainsFunc {
			r.SkipChildren()
			continue
		}

		lr, err := d.LineReader(entry)
		if err != nil || lr == nil {
			continue
		}

		var startEntry, endEntry dwarf.LineEntry
		if err := lr.SeekPC(fnSymbol.Value, &startEntry); err != nil {
			continue
		}

		endEntry = startEntry
		funcEndAddr := fnSymbol.Value + fnSymbol.Size
		currentLineEntry := startEntry
		for {
			if currentLineEntry.Address >= funcEndAddr {
				break
			}
			if startEntry.File != nil && currentLineEntry.File != nil &&
				startEntry.File.Name == currentLineEntry.File.Name &&
				currentLineEntry.Line > endEntry.Line {
				endEntry = currentLineEntry
			}
			if err := lr.Next(&currentLineEntry); err != nil {
				break
			}
		}

		fileName := startEntry.File.Name
		if !filepath.IsAbs(fileName) {
			compDir, _ := entry.Val(dwarf.AttrCompDir).(string)
			fileName = filepath.Join(compDir, fileName)
		}
		if filepath.IsAbs(fileName) {
			parts := strings.Split(fileName, string(filepath.Separator))
			fileName = filepath.Join(parts[5:]...)
		}
		content, err := os.ReadFile(filepath.Join(p.kernelDir, fileName))
		if err != nil {
			return "", fmt.Errorf("failed to read source file %s/%s: %w", p.kernelDir, fileName, err)
		}

		lines := strings.Split(string(content), "\n")
		bodyStartLine := startEntry.Line - 1
		endLine := endEntry.Line
		if endLine > len(lines) {
			endLine = len(lines)
		}
		if bodyStartLine < 0 || bodyStartLine >= endLine {
			return "", fmt.Errorf("invalid line range for function start: %d (end: %d) for file %s", bodyStartLine+1, endLine, fileName)
		}

		signatureLine := -1
		for i := bodyStartLine; i >= 0; i-- {
			if strings.Contains(lines[i], functionName) && strings.Contains(lines[i], "(") {
				signatureLine = i
				break
			}
		}
		if signatureLine == -1 {
			signatureLine = bodyStartLine
		}

		startLine := signatureLine
		if startLine > 0 && strings.TrimSpace(lines[startLine-1]) == "*/" {
			for i := startLine - 2; i >= 0; i-- {
				if strings.Contains(lines[i], "/*") {
					startLine = i
					break
				}
			}
		}

		return strings.Join(lines[startLine:endLine], "\n"), nil
	}

	return "", fmt.Errorf("function %s not found in DWARF info", functionName)
}

// --- WeggliProvider ---

// WeggliProvider uses weggli to find function definitions.
type WeggliProvider struct {
	kernelDir string
}

// FindFunctionDefinition finds a function's source code using the weggli tool.
func (p *WeggliProvider) FindFunctionDefinition(functionName string) (string, error) {
	weggliPattern := fmt.Sprintf("_ %s(){}", functionName)
	cmd := exec.Command("weggli", "--after=9999999", weggliPattern, p.kernelDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("weggli command failed: %w\nOutput: %s", err, string(output))
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return "", fmt.Errorf("weggli found no matches")
	}
	return string(output), nil
}

// --- AstGrepProvider ---

// AstGrepProvider uses ast-grep to find function definitions.
type AstGrepProvider struct {
	kernelDir string
}

// FindFunctionDefinition finds a function's source code using the ast-grep tool.
func (p *AstGrepProvider) FindFunctionDefinition(functionName string) (string, error) {
	astGrepPattern := fmt.Sprintf("$$$ %s($$$ARGS){$$$}", functionName)
	cmd := exec.Command("ast-grep", "run", "--lang=c", "--pattern", astGrepPattern, "--selector", "function_definition", p.kernelDir)
	cmd.Dir = p.kernelDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ast-grep command failed: %w\nOutput: %s", err, string(output))
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return "", fmt.Errorf("ast-grep found no matches")
	}
	return string(output), nil
}
