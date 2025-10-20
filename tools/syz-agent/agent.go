package main

import (
	"fmt"

	"google.golang.org/genai"
)

// ToolHandler defines the function signature for handling a tool's function call.
type ToolHandler func(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error)

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

// Handle dispatches a function call to the appropriate tool's handler.
func (ts *ToolSet) Handle(fc *genai.FunctionCall) (*genai.Part, error) {
	if tool, ok := ts.tools[fc.Name]; ok {
		return tool.Handler(ts, fc)
	}
	return nil, fmt.Errorf("unknown tool function: %s", fc.Name)
}
