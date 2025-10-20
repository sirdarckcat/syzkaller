package main

import (
	"fmt"

	"google.golang.org/genai"
)

// CrashContext provides tools for accessing crash report data.
type CrashContext struct {
	report     string
	reproducer string
}

// NewCrashContext creates a new CrashContext provider.
func NewCrashContext(report, reproducer string) *CrashContext {
	return &CrashContext{
		report:     report,
		reproducer: reproducer,
	}
}

// GetTools returns the set of tools for accessing crash context.
func (cc *CrashContext) GetTools() []*Tool {
	return []*Tool{
		{
			Declaration: genai.FunctionDeclaration{
				Name:        "get_crash_context",
				Description: "Retrieves the crash report and syz-reproducer for the current bug.",
				Parameters:  &genai.Schema{Type: genai.TypeObject},
			},
			Handler: cc.handleGetCrashContext,
			Classes: []string{"crash_analyzer"},
		},
	}
}

func (cc *CrashContext) handleGetCrashContext(ts *ToolSet, fc *genai.FunctionCall) (*genai.Part, error) {
	contextText := fmt.Sprintf(
		"--- Crash Report ---\n%s\n\n--- Syz-Reproducer ---\n%s",
		cc.report, cc.reproducer,
	)
	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     "get_crash_context",
			Response: map[string]any{"output": contextText},
		},
	}, nil
}
