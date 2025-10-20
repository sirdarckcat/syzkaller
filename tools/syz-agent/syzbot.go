package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BugReport defines the structure for the syzbot JSON response.
type BugReport struct {
	Crashes []Crash `json:"crashes"`
}

// Crash holds the details for a single crash instance.
type Crash struct {
	KernelRepo      string `json:"kernel-source-git"`
	KernelCommit    string `json:"kernel-source-commit"`
	SyzReproducer   string `json:"syz-reproducer"`
	CrashReportLink string `json:"crash-report-link"`
	KernelConfig    string `json:"kernel-config"`
}

// fetchCrashDetails fetches and parses the crash details from a syzbot URL.
func fetchCrashDetails(urlStr string) (*Crash, error) {
	resp, err := http.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL %s: %w", urlStr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	var report BugReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	if len(report.Crashes) == 0 {
		return nil, fmt.Errorf("no crashes found in the report")
	}

	return &report.Crashes[0], nil
}

// fetchTextData fetches plain text content from a syzkaller URL.
func fetchTextData(baseURL, relativeURL string) (string, error) {
	if relativeURL == "" {
		return "", nil // Nothing to fetch
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse base URL: %w", err)
	}
	rel, err := url.Parse(relativeURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse relative URL: %w", err)
	}
	fullURL := base.ResolveReference(rel)
	fmt.Printf("Fetching data from: %s\n", fullURL.String())

	resp, err := http.Get(fullURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to fetch text data from %s: %w", fullURL.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status when fetching text data from %s: %s", fullURL.String(), resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

// cleanRepoURL converts a kernel.org log URL to a cloneable git URL.
func cleanRepoURL(logURL string) string {
	if idx := strings.Index(logURL, ".git"); idx != -1 {
		return logURL[:idx+4]
	}
	return logURL
}
