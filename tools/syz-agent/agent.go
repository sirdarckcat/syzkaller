package main

import (
	"fmt"

	"google.golang.org/genai"
)

// Tool represents a single function the agent can call.
type Tool struct {
	Declaration genai.FunctionDeclaration
	// The handler now receives a pointer to the ToolSet.
	Handler func(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error)
}

// ToolProvider is an interface for components that can provide agent tools.
type ToolProvider interface {
	GetTools() []*Tool
}

// ToolSet aggregates tools from multiple providers and handles dispatch.
type ToolSet struct {
	tools map[string]*Tool
}

// NewToolSet creates a new ToolSet and registers tools from the given providers.
func NewToolSet(providers ...ToolProvider) *ToolSet {
	ts := &ToolSet{
		tools: make(map[string]*Tool),
	}
	for _, provider := range providers {
		// Explicitly skip any nil providers to prevent panics.
		if provider == nil {
			continue
		}
		for _, tool := range provider.GetTools() {
			ts.tools[tool.Declaration.Name] = tool
		}
	}
	return ts
}

// GetToolConfig builds the genai.Tool configuration from all registered tools.
func (ts *ToolSet) GetToolConfig() *genai.Tool {
	var declarations []*genai.FunctionDeclaration
	for _, tool := range ts.tools {
		declarations = append(declarations, &tool.Declaration)
	}
	return &genai.Tool{FunctionDeclarations: declarations}
}

// Handle finds the appropriate handler for a function call and executes it.
func (ts *ToolSet) Handle(fc *genai.FunctionCall) (*genai.Part, error) {
	if tool, ok := ts.tools[fc.Name]; ok {
		// Pass the ToolSet to the handler.
		return tool.Handler(ts, fc)
	}
	return nil, fmt.Errorf("agent called unknown function: %s", fc.Name)
}
