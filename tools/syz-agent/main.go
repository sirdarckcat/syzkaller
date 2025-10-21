package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/tool"
	"google.golang.org/genai"
)

var (
	// Main application flags
	flagURL    = flag.String("syzkaller-url", "", "syzbot bug URL with json=1")
	flagAPIKey = flag.String("api-key", "", "Your GenAI API Key")

	// Kernel build flags
	flagBuildKernel = flag.Bool("build-kernel", false, "Build the kernel at the specified commit before running")
	flagBuildJobs   = flag.Int("build-jobs", runtime.NumCPU(), "Number of parallel jobs for building the kernel")

	// GDB executor flags
	flagKernelCheckout = flag.String("kernel_checkout", "", "path to kernel build directory (for objdump) or vmlinux file URL")
	flagDiskImage      = flag.String("disk_image", "https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz", "path to disk image file or URL")
	flagKernelBZImage  = flag.String("kernel_bzimage", "", "path to kernel image (e.g., bzImage) or URL")
	flagDebug          = flag.Bool("debug", false, "enable debug output for VM and executor")
)

// printToolOutputPreview prints the first 30 lines of a tool's output to the console.
func printToolOutputPreview(toolName, output string) {
	fmt.Printf("\n--- Tool Output Preview: %s ---\n", toolName)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for i := 0; i < 30 && scanner.Scan(); i++ {
		fmt.Println(scanner.Text())
	}
	if scanner.Scan() {
		fmt.Println("... (output continues)")
	}
	fmt.Println("---------------------------------")
}

// generateContentWithTools manages a stateless conversation with the model, including tool calls.
func generateContentWithTools(ctx context.Context, client *genai.Client, rawPrompt string, toolSet *ToolSet, history []*genai.Content) (string, []*genai.Content, error) {
	agentClass, prompt := parsePrompt(rawPrompt)
	var tools *genai.Tool
	if agentClass != "" {
		fmt.Printf("--- Using agent class: %s ---\n", agentClass)
		tools = toolSet.GetToolConfigForClass(agentClass)
		if tools == nil || len(tools.FunctionDeclarations) == 0 {
			return "", history, fmt.Errorf("no tools found for agent class '%s'", agentClass)
		}
	} else {
		fmt.Println("--- Using all available tools (no class specified) ---")
		tools = toolSet.GetToolConfig()
	}

	fmt.Printf("\n--- Sending prompt to agent: '%s' ---\n", prompt)

	thinkingBudget := int32(-1)
	config := &genai.GenerateContentConfig{
		Tools:       []*genai.Tool{tools},
		Temperature: genai.Ptr[float32](0.0),
		ThinkingConfig: &genai.ThinkingConfig{
			IncludeThoughts: true,
			ThinkingBudget:  &thinkingBudget,
		},
	}

	history = append(history, &genai.Content{
		Parts: []*genai.Part{{Text: prompt}},
		Role:  "user",
	})

	for {
		resp, err := client.Models.GenerateContent(ctx, "gemini-2.5-pro", history, config)
		if err != nil {
			return "", history, fmt.Errorf("failed to generate content: %w", err)
		}

		if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
			if *flagDebug {
				jsonResp, jsonErr := json.MarshalIndent(resp, "", "  ")
				if jsonErr != nil {
					fmt.Printf("--- DEBUG: Failed to marshal response to JSON: %v ---\n", jsonErr)
					fmt.Printf("--- DEBUG: Raw Response: %+v ---\n", resp)
				} else {
					fmt.Printf("--- DEBUG: Received invalid/empty response from model ---\n%s\n----------------------------------------------------------\n", string(jsonResp))
				}
			}
			return "", history, fmt.Errorf("received empty or invalid response from model")
		}

		modelResponse := resp.Candidates[0].Content
		history = append(history, modelResponse)

		var finalAnswer string
		var funcResponse *genai.Part

		for _, part := range modelResponse.Parts {
			if part.Thought {
				fmt.Printf("\n--- Model Thought ---\n%s\n---------------------\n", part.Text)
				continue
			}
			if part.FunctionCall != nil {
				funcResponse, err = toolSet.Handle(part.FunctionCall)
				if err != nil {
					return "", history, fmt.Errorf("error handling function call '%s': %w", part.FunctionCall.Name, err)
				}
				// Centralized output preview logic.
				if funcResponse != nil && funcResponse.FunctionResponse != nil {
					if output, ok := funcResponse.FunctionResponse.Response["output"].(string); ok {
						printToolOutputPreview(part.FunctionCall.Name, output)
					}
				}
				break
			}
			if part.Text != "" {
				finalAnswer += part.Text
			}
		}

		if funcResponse != nil {
			history = append(history, &genai.Content{
				Parts: []*genai.Part{funcResponse},
				Role:  "function",
			})
			continue // Continue the conversation loop
		}

		if finalAnswer != "" {
			return finalAnswer, history, nil // The conversation is finished
		}

		if *flagDebug {
			jsonResp, jsonErr := json.MarshalIndent(resp, "", "  ")
			if jsonErr != nil {
				fmt.Printf("--- DEBUG: Failed to marshal response to JSON: %v ---\n", jsonErr)
				fmt.Printf("--- DEBUG: Raw Response: %+v ---\n", resp)
			} else {
				fmt.Printf("--- DEBUG: Not possible to proceed from current state ---\n%s\n----------------------------------------------------------\n", string(jsonResp))
			}
		}
		return "", nil, fmt.Errorf("model response contained no actionable content (text or function call)")
	}
}

// parsePrompt splits a raw prompt into an agent class and the actual prompt.
// e.g., "code_explorer:find the code of x" -> "code_explorer", "find the code of x"
func parsePrompt(rawPrompt string) (string, string) {
	parts := strings.SplitN(rawPrompt, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return "", rawPrompt // No class specified
}

// precacheResources checks for remote resources and downloads them into the cache at startup.
func precacheResources() {
	fmt.Println("--- Pre-caching external resources... ---")
	var wg sync.WaitGroup
	hasDownloads := false

	if strings.HasPrefix(*flagDiskImage, "http") {
		hasDownloads = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("Caching disk image...")
			if _, cleanup, err := HandleFileFlag(*flagDiskImage); err != nil {
				fmt.Printf("Warning: failed to pre-cache disk image: %v\n", err)
			} else {
				cleanup()
			}
		}()
	}

	if strings.HasPrefix(*flagKernelBZImage, "http") {
		hasDownloads = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("Caching kernel bzImage...")
			if _, cleanup, err := HandleFileFlag(*flagKernelBZImage); err != nil {
				fmt.Printf("Warning: failed to pre-cache kernel bzImage: %v\n", err)
			} else {
				cleanup()
			}
		}()
	}

	if strings.HasPrefix(*flagKernelCheckout, "http") {
		hasDownloads = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println("Caching vmlinux...")
			// Use handleKernelObj for vmlinux to ensure it's placed in a directory
			if _, cleanup, err := handleKernelObj(*flagKernelCheckout); err != nil {
				fmt.Printf("Warning: failed to pre-cache kernel checkout/vmlinux: %v\n", err)
			} else {
				cleanup()
			}
		}()
	}

	if hasDownloads {
		wg.Wait()
		fmt.Println("--- Pre-caching finished. ---")
	} else {
		fmt.Println("--- No external resources to pre-cache. ---")
	}
}

func main() {
	tool.Init()
	flag.Parse()
	flagPrompts := flag.Args()

	if *flagURL == "" || len(flagPrompts) == 0 || *flagAPIKey == "" {
		tool.Failf("All --syzkaller-url, --api-key and at least one prompt argument are required")
	}

	// Ensure the cache directory exists before any caching can occur.
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		tool.Failf("failed to create cache directory: %v", err)
	}

	precacheResources()

	// 1. Fetch Crash Details
	crash, err := fetchCrashDetails(*flagURL)
	if err != nil {
		tool.Failf("Error fetching crash details: %v", err)
	}
	fmt.Printf("Found crash with commit %s from repo %s\n", crash.KernelCommit, cleanRepoURL(crash.KernelRepo))

	crashReport, err := fetchTextData(*flagURL, crash.CrashReportLink)
	if err != nil {
		fmt.Printf("Warning: could not fetch crash report: %v\n", err)
	}
	syzReproducer, err := fetchTextData(*flagURL, crash.SyzReproducer)
	if err != nil {
		fmt.Printf("Warning: could not fetch syz-reproducer: %v\n", err)
	}

	var kernelConfig []byte
	if crash.KernelConfig != "" {
		fmt.Println("--- Fetching kernel config from syzbot ---")
		configText, err := fetchTextData(*flagURL, crash.KernelConfig)
		if err != nil {
			fmt.Printf("Warning: could not fetch kernel config: %v\n", err)
		} else {
			kernelConfig = []byte(configText)
			fmt.Println("--- Successfully fetched kernel config ---")
		}
	}

	// 2. Checkout Kernel
	kernelRepo, err := newRepo(cleanRepoURL(crash.KernelRepo), crash.KernelCommit)
	if err != nil {
		tool.Failf("Error checking out kernel: %v", err)
	}
	fmt.Printf("\nSuccess! Kernel is ready at: %s\n", kernelRepo.Dir)

	// --- Potentially build the kernel ---
	var buildResultChan chan *BuildResult
	if *flagBuildKernel {
		buildResultChan = make(chan *BuildResult, 1)
		go func() {
			defer close(buildResultChan)
			fmt.Println("--- Starting parallel kernel build... ---")
			imgPath, vmlinuxPath, err := kernelRepo.Build(*flagBuildJobs, kernelConfig, *flagDebug)
			if err != nil {
				fmt.Printf("--- Parallel kernel build failed: %v ---\n", err)
				buildResultChan <- &BuildResult{Err: err}
				return
			}
			fmt.Println("--- Parallel kernel build finished successfully! ---")
			buildResultChan <- &BuildResult{
				KernelImagePath: imgPath,
				VmlinuxPath:     vmlinuxPath,
			}
		}()
	}

	// 3. Setup GenAI Client
	ctx := context.Background()
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  *flagAPIKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		tool.Failf("Failed to create GenAI client: %v", err)
	}

	// 4. Compose Agent from different providers
	kernelObj := *flagKernelCheckout
	if buildResultChan != nil {
		// Wait for the build to finish to get the vmlinux path.
		res := <-buildResultChan
		kernelObj = res.VmlinuxPath
	}
	providers := []ToolProvider{
		NewCodeExplorer(kernelRepo.Dir, kernelObj),
		NewCrashContext(crashReport, syzReproducer),
	}

	if (*flagKernelCheckout != "" && *flagKernelBZImage != "") || *flagBuildKernel {
		fmt.Println("SyzExecutor enabled.")
		syzkallerPath, err := os.Getwd()
		if err != nil {
			tool.Failf("failed to get current working directory: %v", err)
		}
		providers = append(providers, NewSyzExecutor(SyzExecutorConfig{
			SyzkallerPath:   syzkallerPath,
			KernelDir:       kernelRepo.Dir,
			KernelCheckout:  *flagKernelCheckout,
			DiskImage:       *flagDiskImage,
			KernelBZImage:   *flagKernelBZImage,
			Debug:           *flagDebug,
			BuildResultChan: buildResultChan,
		}))
	} else {
		fmt.Println("SyzExecutor disabled (kernel artifacts not provided and --build-kernel=false).")
	}

	toolSet := NewToolSet(providers...)

	// 5. Run Conversation Loop
	var history []*genai.Content
	for _, rawPrompt := range flagPrompts {
		var finalResponse string
		finalResponse, history, err = generateContentWithTools(ctx, client, rawPrompt, toolSet, history)
		if err != nil {
			tool.Failf("Error in agent conversation for prompt '%s': %v", rawPrompt, err)
		}
		_, prompt := parsePrompt(rawPrompt)
		fmt.Printf("\n--- Agent's Final Response for: '%s' ---\n", prompt)
		fmt.Println(finalResponse)
		fmt.Println(strings.Repeat("=", 80))
	}
}
