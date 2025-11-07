package main

import (
	"context"
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
	flagURL            = flag.String("syzkaller-url", "", "syzbot bug URL with json=1")
	flagAPIKey         = flag.String("api-key", "", "Your GenAI API Key")
	flagBuildKernel    = flag.Bool("build-kernel", false, "Build the kernel at the specified commit before running")
	flagBuildJobs      = flag.Int("build-jobs", runtime.NumCPU(), "Number of parallel jobs for building the kernel")
	flagKernelCheckout = flag.String("kernel_checkout", "", "path to kernel build directory (for objdump) or vmlinux file URL")
	flagDiskImage      = flag.String("disk_image", "https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz", "path to disk image file or URL")
	flagKernelBZImage  = flag.String("kernel_bzimage", "", "path to kernel image (e.g., bzImage) or URL")
	flagDebug          = flag.Bool("debug", false, "enable debug output for VM and executor")
)

func precacheResources() {
	fmt.Println("--- Pre-caching external resources... ---")
	var wg sync.WaitGroup
	hasDownloads := false

	if strings.HasPrefix(*flagDiskImage, "http") {
		hasDownloads = true
		wg.Add(1)
		go func() {
			defer wg.Done()
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
			if _, cleanup, err := HandleKernelObj(*flagKernelCheckout); err != nil {
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

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		tool.Failf("failed to create cache directory: %v", err)
	}
	precacheResources()

	crash, err := fetchCrashDetails(*flagURL)
	if err != nil {
		tool.Failf("Error fetching crash details: %v", err)
	}
	fmt.Printf("Found crash with commit %s from repo %s\n", crash.KernelCommit, cleanRepoURL(crash.KernelRepo))

	crashReport, _ := fetchTextData(*flagURL, crash.CrashReportLink)
	syzReproducer, _ := fetchTextData(*flagURL, crash.SyzReproducer)
	var kernelConfig []byte
	if crash.KernelConfig != "" {
		configText, _ := fetchTextData(*flagURL, crash.KernelConfig)
		kernelConfig = []byte(configText)
	}

	kernelRepo, err := newRepo(cleanRepoURL(crash.KernelRepo), crash.KernelCommit)
	if err != nil {
		tool.Failf("Error checking out kernel: %v", err)
	}
	fmt.Printf("\nSuccess! Kernel is ready at: %s\n", kernelRepo.Dir)

	// Build the cscope database synchronously.
	cscopeProvider, err := NewCscopeProvider(kernelRepo.Dir)
	if err != nil {
		tool.Failf("Failed to build cscope database: %v", err)
	}

	var buildResultChan chan *BuildResult
	if *flagBuildKernel {
		buildResultChan = make(chan *BuildResult, 1)
		go func() {
			defer close(buildResultChan)
			imgPath, vmlinuxPath, err := kernelRepo.Build(*flagBuildJobs, kernelConfig, *flagDebug)
			buildResultChan <- &BuildResult{KernelImagePath: imgPath, VmlinuxPath: vmlinuxPath, Err: err}
		}()
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, &genai.ClientConfig{APIKey: *flagAPIKey, Backend: genai.BackendGeminiAPI})
	if err != nil {
		tool.Failf("Failed to create GenAI client: %v", err)
	}

	weggliProvider := &WeggliProvider{kernelDir: kernelRepo.Dir}
	toolSet := initializeTools(kernelRepo.Dir, crashReport, syzReproducer, cscopeProvider, weggliProvider, buildResultChan)
	agent := NewAgent(client, toolSet)

	for _, p := range flagPrompts {
		rawPrompt := p
		// If a prompt starts with @, treat it as a file path and read the content.
		if strings.HasPrefix(p, "@") {
			filePath := strings.TrimPrefix(p, "@")
			content, err := os.ReadFile(filePath)
			if err != nil {
				tool.Failf("failed to read prompt file %s: %v", filePath, err)
			}
			rawPrompt = string(content)
		} else if strings.Contains(p, ":@") {
			parts := strings.SplitN(p, ":@", 2)
			if len(parts) == 2 {
				agentClass, filePath := parts[0], parts[1]
				content, err := os.ReadFile(filePath)
				if err != nil {
					tool.Failf("failed to read prompt file %s: %v", filePath, err)
				}
				rawPrompt = fmt.Sprintf("%s: %s", agentClass, string(content))
			}
		}

		finalResponse, err := agent.RunPrompt(ctx, rawPrompt)
		if err != nil {
			tool.Failf("Error in agent conversation for prompt '%s': %v", p, err)
		}
		_, promptText := parsePrompt(p)
		fmt.Printf("\n--- Agent's Final Response for: '%s' ---\n", promptText)
		fmt.Println(finalResponse)
		fmt.Println(strings.Repeat("=", 80))
	}
}
