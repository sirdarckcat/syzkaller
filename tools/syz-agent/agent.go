package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/genai"
)

// Agent manages a conversation with the GenAI model.
type Agent struct {
	client  *genai.Client
	toolSet *ToolSet
	history []*genai.Content
	config  *genai.GenerateContentConfig
}

// NewAgent creates a new conversation agent.
func NewAgent(client *genai.Client, toolSet *ToolSet) *Agent {
	thinkingBudget := int32(-1)
	config := &genai.GenerateContentConfig{
		Temperature: genai.Ptr[float32](0.0),
		ThinkingConfig: &genai.ThinkingConfig{
			IncludeThoughts: true,
			ThinkingBudget:  &thinkingBudget,
		},
	}
	return &Agent{
		client:  client,
		toolSet: toolSet,
		config:  config,
	}
}

// RunPrompt is the main entry point for a user's prompt. It orchestrates the conversation loop.
func (a *Agent) RunPrompt(ctx context.Context, rawPrompt string) (string, error) {
	// Prepare the tool configuration for this specific prompt.
	agentClass, prompt := parsePrompt(rawPrompt)
	var tools *genai.Tool
	if agentClass != "" {
		fmt.Printf("--- Using agent class: %s ---\n", agentClass)
		tools = a.toolSet.GetToolConfigForClass(agentClass)
		if tools == nil || len(tools.FunctionDeclarations) == 0 {
			return "", fmt.Errorf("no tools found for agent class '%s'", agentClass)
		}
	} else {
		fmt.Println("--- Using all available tools (no class specified) ---")
		tools = a.toolSet.GetToolConfig()
	}
	a.config.Tools = []*genai.Tool{tools}

	fmt.Printf("\n--- Sending prompt to agent: '%s' ---\n", prompt)
	a.history = append(a.history, &genai.Content{
		Parts: []*genai.Part{{Text: prompt}},
		Role:  "user",
	})

	// Loop until the model provides a final answer instead of a tool call.
	for {
		resp, err := a.generateWithRetry(ctx)
		if err != nil {
			return "", err
		}

		finalAnswer, shouldContinue, err := a.processResponse(resp)
		if err != nil {
			return "", err
		}
		if !shouldContinue {
			return finalAnswer, nil
		}
	}
}

// generateWithRetry calls the GenAI model with an exponential backoff retry mechanism.
func (a *Agent) generateWithRetry(ctx context.Context) (*genai.GenerateContentResponse, error) {
	const maxRetries = 3
	const initialBackoff = 2 * time.Second

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		resp, err := a.client.Models.GenerateContent(ctx, "gemini-2.5-pro", a.history, a.config)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		fmt.Printf("GenAI API call failed (attempt %d/%d): %v\n", i+1, maxRetries, err)
		if i < maxRetries-1 {
			backoff := initialBackoff * time.Duration(1<<(i))
			fmt.Printf("Retrying in %v...\n", backoff)
			time.Sleep(backoff)
		}
	}
	return nil, fmt.Errorf("failed to generate content after %d attempts: %w", maxRetries, lastErr)
}

// processResponse handles the model's response, processing tool calls or extracting the final answer.
// It returns the final answer (if found), a boolean indicating if the loop should continue, and an error.
func (a *Agent) processResponse(resp *genai.GenerateContentResponse) (string, bool, error) {
	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return "", false, fmt.Errorf("received empty or invalid response from model")
	}

	modelResponse := resp.Candidates[0].Content
	a.history = append(a.history, modelResponse)

	var finalAnswer string
	var funcResponse *genai.Part
	var err error

	for _, part := range modelResponse.Parts {
		if part.Thought {
			fmt.Printf("\n--- Model Thought ---\n%s\n---------------------\n", part.Text)
			continue
		}
		if part.FunctionCall != nil {
			funcResponse, err = a.toolSet.Handle(part.FunctionCall)
			if err != nil {
				return "", false, fmt.Errorf("error handling function call '%s': %w", part.FunctionCall.Name, err)
			}
			break
		}
		if part.Text != "" {
			finalAnswer += part.Text
		}
	}

	if funcResponse != nil {
		a.history = append(a.history, &genai.Content{
			Parts: []*genai.Part{funcResponse},
			Role:  "function",
		})
		return "", true, nil // Continue the conversation loop.
	}

	if finalAnswer != "" {
		return finalAnswer, false, nil // Conversation finished.
	}

	return "", false, fmt.Errorf("model response contained no actionable content")
}

func parsePrompt(rawPrompt string) (string, string) {
	parts := strings.SplitN(rawPrompt, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return "", rawPrompt
}
