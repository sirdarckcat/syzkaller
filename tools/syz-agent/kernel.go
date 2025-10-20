package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/vcs"
)

// Repo represents a checked-out kernel repository.
type Repo struct {
	Dir string
}

// ConsoleTracer implements the debugtracer.DebugTracer interface to print logs to the console.
type ConsoleTracer struct{}

func (ct *ConsoleTracer) Log(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (ct *ConsoleTracer) SaveFile(name string, data []byte) {
	// We don't need to save files for this use case, but the interface requires the method.
}

// newRepo safely clones/updates the repo and checks out the commit.
func newRepo(repoURL, commit string) (*Repo, error) {
	cacheDir := filepath.Join("/tmp", "syzkaller-repo-cache", "linux")
	repo, err := vcs.NewRepo("linux", "qemu", cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create repo object: %w", err)
	}

	fmt.Printf("Fetching/checking out commit %s in %s...\n", commit, cacheDir)
	if _, err := repo.CheckoutCommit(repoURL, commit); err != nil {
		return nil, fmt.Errorf("failed to checkout commit: %w", err)
	}

	absPath, err := filepath.Abs(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}
	return &Repo{Dir: absPath}, nil
}

// Build compiles the kernel using the syzkaller build system.
func (r *Repo) Build(jobs int, kernelConfig []byte, debug bool) (string, string, error) {
	log.EnableLogCaching(10000, 10000)
	fmt.Printf("\n--- Building kernel in %s with %d jobs (using syzkaller builder) ---\n", r.Dir, jobs)

	outputDir, err := os.MkdirTemp("", "syz-kernel-build-")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp build dir: %w", err)
	}

	if kernelConfig == nil {
		return "", "", fmt.Errorf("kernel config must be provided for the build")
	}

	var tracer debugtracer.DebugTracer
	if debug {
		tracer = &ConsoleTracer{}
	}

	params := build.Params{
		TargetOS:   "linux",
		TargetArch: "amd64",
		KernelDir:  r.Dir,
		OutputDir:  outputDir,
		Config:     kernelConfig,
		BuildCPUs:  jobs,
		Tracer:     tracer,
	}

	// build.Image compiles the kernel and places artifacts in OutputDir.
	_, err = build.Image(params)
	if err != nil {
		return "", "", fmt.Errorf("kernel build failed: %w", err)
	}

	kernelImagePath := filepath.Join(outputDir, "kernel")
	vmlinuxPath := filepath.Join(outputDir, "obj", "vmlinux")

	if _, err := os.Stat(kernelImagePath); err != nil {
		return "", "", fmt.Errorf("kernel image not found at %s after build", kernelImagePath)
	}
	if _, err := os.Stat(vmlinuxPath); err != nil {
		return "", "", fmt.Errorf("vmlinux file not found at %s after build", vmlinuxPath)
	}

	fmt.Println("--- Kernel build successful ---")
	return kernelImagePath, vmlinuxPath, nil
}
