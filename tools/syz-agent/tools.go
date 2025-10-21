package main

import (
	"fmt"
	"os"
)

// initializeTools creates and configures all the tool providers for the agent.
func initializeTools(kernelDir, crashReport, syzReproducer string, buildResultChan chan *BuildResult) *ToolSet {
	// Wait for a potential build to finish to get the correct vmlinux path.
	kernelObj := *flagKernelCheckout
	if buildResultChan != nil {
		res := <-buildResultChan
		if res.Err != nil {
			// If the build failed, we can still proceed without the executor tools.
			// The executor will report the build failure if its tools are used.
			fmt.Printf("Warning: kernel build failed. SyzExecutor tools may not function correctly: %v\n", res.Err)
		} else if res.VmlinuxPath != "" {
			kernelObj = res.VmlinuxPath
		}
	}

	providers := []ToolProvider{
		NewCodeExplorer(kernelDir, kernelObj),
		NewCrashContext(crashReport, syzReproducer),
	}

	// The executor is a powerful tool, but it requires a valid kernel build.
	// Only enable it if we have the necessary artifacts.
	if (*flagKernelCheckout != "" && *flagKernelBZImage != "") || *flagBuildKernel {
		fmt.Println("SyzExecutor enabled.")
		syzkallerPath, err := os.Getwd()
		if err != nil {
			// This is a fatal error for the executor.
			fmt.Printf("Critical: failed to get current working directory for SyzExecutor: %v\n", err)
		} else {
			providers = append(providers, NewSyzExecutor(SyzExecutorConfig{
				SyzkallerPath:   syzkallerPath,
				KernelDir:       kernelDir,
				KernelCheckout:  *flagKernelCheckout,
				DiskImage:       *flagDiskImage,
				KernelBZImage:   *flagKernelBZImage,
				Debug:           *flagDebug,
				BuildResultChan: buildResultChan,
			}))
		}
	} else {
		fmt.Println("SyzExecutor disabled (kernel artifacts not provided and --build-kernel=false).")
	}

	return NewToolSet(providers...)
}
