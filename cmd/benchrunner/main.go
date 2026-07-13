package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type SystemMetadata struct {
	Timestamp   string `json:"timestamp"`
	OS          string `json:"os"`
	Architecture string `json:"architecture"`
	CPU         string `json:"cpu"`
	RAM         string `json:"ram"`
	GoVersion   string `json:"go_version"`
	DockerMode  bool   `json:"docker_mode"`
	GitCommit   string `json:"git_commit"`
}

type BenchmarkResult struct {
	Name        string  `json:"name"`
	Iterations  int64   `json:"iterations"`
	NsPerOp     float64 `json:"ns_per_op"`
	BytesPerOp  int64   `json:"bytes_per_op"`
	AllocsPerOp int64   `json:"allocs_per_op"`
}

type Report struct {
	Metadata   SystemMetadata    `json:"metadata"`
	Benchmarks []BenchmarkResult `json:"benchmarks"`
}

func main() {
	suffix := flag.String("suffix", "", "suffix for result filenames")
	flag.Parse()

	fmt.Println("=== Starting FlowGuard Lite Benchmark Runner ===")
	
	// 1. Gather Metadata
	meta := gatherMetadata()
	fmt.Printf("System Metadata resolved:\n")
	fmt.Printf("  OS/Arch: %s/%s\n", meta.OS, meta.Architecture)
	fmt.Printf("  CPU:     %s\n", meta.CPU)
	fmt.Printf("  RAM:     %s\n", meta.RAM)
	fmt.Printf("  Go:      %s\n", meta.GoVersion)
	fmt.Printf("  Docker:  %t\n", meta.DockerMode)
	fmt.Printf("  Commit:  %s\n", meta.GitCommit)

	// 2. Run the Benchmark Command
	fmt.Println("\nRunning benchmarks (go test -bench=. -benchmem ./internal/benchmark)...")
	cmd := exec.Command("go", "test", "-bench=.", "-benchmem", "./internal/benchmark")
	var stdoutBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Warning: benchmark command execution finished with error: %v\n", err)
	}

	// 3. Parse Benchmark Output
	benchmarks := parseBenchmarkOutput(stdoutBuf.String())
	fmt.Printf("Parsed %d benchmarks from execution output.\n", len(benchmarks))

	// 4. Generate Reports
	report := Report{
		Metadata:   meta,
		Benchmarks: benchmarks,
	}

	err = writeReports(report, *suffix)
	if err != nil {
		fmt.Printf("Error writing reports: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== Benchmark Runner completed successfully! ===")
	fmt.Println("Outputs generated:")
	if *suffix != "" {
		fmt.Printf("  JSON:      benchmark-results/results-%s.json\n", *suffix)
		fmt.Printf("  Markdown:  benchmark-results/results-%s.md\n", *suffix)
	} else {
		fmt.Println("  JSON:      benchmark-results/results.json")
		fmt.Println("  Markdown:  benchmark-results/results.md")
	}
}

func gatherMetadata() SystemMetadata {
	return SystemMetadata{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPU:          getCPUBrand(),
		RAM:          getMemorySize(),
		GoVersion:    runtime.Version(),
		DockerMode:   isDocker(),
		GitCommit:    getGitCommit(),
	}
}

func getCPUBrand() string {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	} else if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/cpuinfo")
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "model name") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	return "Unknown CPU"
}

func getMemorySize() string {
	if limit := os.Getenv("FLOWGUARD_BENCH_MEM_LIMIT"); limit != "" {
		return limit
	}

	if runtime.GOOS == "darwin" {
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err == nil {
			bytes, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
			if err == nil {
				return fmt.Sprintf("%.2f GB", float64(bytes)/1024/1024/1024)
			}
		}
	} else if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/meminfo")
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "MemTotal:") {
					parts := strings.Fields(line)
					if len(parts) > 1 {
						val, err := strconv.ParseUint(parts[1], 10, 64)
						if err == nil {
							return fmt.Sprintf("%.2f GB", float64(val*1024)/1024/1024/1024)
						}
					}
				}
			}
		}
	}
	return "Unknown Memory"
}

func getGitCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return "unknown"
}

func isDocker() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func parseBenchmarkOutput(output string) []BenchmarkResult {
	var results []BenchmarkResult
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	// Regex pattern: matches standard Go benchmark line
	var benchRegex = regexp.MustCompile(`^(Benchmark\S+)\s+(\d+)\s+([\d\.]+)\s+ns/op(?:\s+(\d+)\s+B/op\s+(\d+)\s+allocs/op)?`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := benchRegex.FindStringSubmatch(line)
		if len(matches) >= 4 {
			name := matches[1]
			iters, _ := strconv.ParseInt(matches[2], 10, 64)
			ns, _ := strconv.ParseFloat(matches[3], 64)
			
			var bytes int64
			var allocs int64
			if len(matches) >= 6 && matches[4] != "" {
				bytes, _ = strconv.ParseInt(matches[4], 10, 64)
				allocs, _ = strconv.ParseInt(matches[5], 10, 64)
			}

			results = append(results, BenchmarkResult{
				Name:        name,
				Iterations:  iters,
				NsPerOp:     ns,
				BytesPerOp:  bytes,
				AllocsPerOp: allocs,
			})
		}
	}
	return results
}

func writeReports(report Report, suffix string) error {
	dir := "benchmark-results"
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	jsonName := "results.json"
	mdName := "results.md"
	if suffix != "" {
		jsonName = fmt.Sprintf("results-%s.json", suffix)
		mdName = fmt.Sprintf("results-%s.md", suffix)
	}

	// 1. Write JSON
	jsonPath := filepath.Join(dir, jsonName)
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	err = os.WriteFile(jsonPath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	// 2. Write Markdown
	mdPath := filepath.Join(dir, mdName)
	var md bytes.Buffer
	
	md.WriteString("# FlowGuard Lite Performance Benchmark Report\n\n")
	md.WriteString(fmt.Sprintf("Generated on: `%s`  \n", report.Metadata.Timestamp))
	md.WriteString(fmt.Sprintf("Git Commit:   `%s`  \n", report.Metadata.GitCommit))
	md.WriteString(fmt.Sprintf("Docker Mode:  `%t`  \n\n", report.Metadata.DockerMode))

	md.WriteString("## System Metadata\n\n")
	md.WriteString("| Property | Value |\n")
	md.WriteString("| --- | --- |\n")
	md.WriteString(fmt.Sprintf("| OS / Arch | %s / %s |\n", report.Metadata.OS, report.Metadata.Architecture))
	md.WriteString(fmt.Sprintf("| CPU Brand | %s |\n", report.Metadata.CPU))
	md.WriteString(fmt.Sprintf("| RAM Size | %s |\n", report.Metadata.RAM))
	md.WriteString(fmt.Sprintf("| Go Version | %s |\n\n", report.Metadata.GoVersion))

	md.WriteString("## Benchmark Run Summary\n\n")
	md.WriteString("| Benchmark Target | Iterations | Speed (ns/op) | Allocations (B/op) | Allocations (count/op) |\n")
	md.WriteString("| --- | --- | --- | --- | --- |\n")
	
	for _, b := range report.Benchmarks {
		md.WriteString(fmt.Sprintf("| %s | %d | %.2f | %d | %d |\n", 
			b.Name, b.Iterations, b.NsPerOp, b.BytesPerOp, b.AllocsPerOp))
	}
	
	md.WriteString("\n---\n*Report generated automatically by FlowGuard Lite benchmark runner.*\n")

	err = os.WriteFile(mdPath, md.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to write Markdown file: %w", err)
	}

	return nil
}
