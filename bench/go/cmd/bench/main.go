// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func main() {
	runs := flag.Int("runs", 7, "Number of timed iterations per scenario")
	jsonPath := flag.String("json", "", "Path to write JSON results file")
	scenariosFlag := flag.String("scenarios", "", "Comma-separated list of scenario names to run (default: all)")
	flag.Parse()

	selectedScenarios := map[string]bool{}
	if *scenariosFlag != "" {
		for _, s := range strings.Split(*scenariosFlag, ",") {
			selectedScenarios[strings.TrimSpace(s)] = true
		}
	}

	scenarios := allScenarios()

	var suites []suite
	for _, sc := range scenarios {
		if len(selectedScenarios) > 0 && !selectedScenarios[sc.name] {
			continue
		}

		fmt.Printf("Running: %s", sc.name)
		// Warmup run (not recorded).
		sc.run(1)
		metrics := sc.run(*runs)
		fmt.Println()

		// Print console summary
		for _, m := range metrics {
			if len(m.Values) == 0 {
				continue
			}
			mean := trimmedMean(m.Values)
			fmt.Printf("  %s: %.4f %s (trimmed mean)\n", m.Name, mean, m.Unit)
		}

		suites = append(suites, suite{
			Category: sc.category,
			Name:     sc.name,
			Tags:     sc.tags,
			Metrics:  metrics,
		})
	}

	if *jsonPath != "" {
		results := benchmarkResults{
			Metadata: metadata{
				Platform:        "go",
				PlatformVersion: runtime.Version(),
				OS:              runtime.GOOS + "-" + runtime.GOARCH,
				Timestamp:       time.Now().UTC().Format(time.RFC3339),
				RunCount:        *runs,
				GitCommit:       getGitCommit(),
			},
			Suites: suites,
		}

		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*jsonPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("JSON results written to %s\n", *jsonPath)
	}
}

func getGitCommit() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func trimmedMean(values []float64) float64 {
	if len(values) <= 2 {
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		return sum / float64(len(values))
	}

	// Copy and find min/max indices
	sorted := make([]float64, len(values))
	copy(sorted, values)
	// Simple sort for small arrays
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Discard first and last
	trimmed := sorted[1 : len(sorted)-1]
	sum := 0.0
	for _, v := range trimmed {
		sum += v
	}
	return sum / float64(len(trimmed))
}

// allScenarios returns all benchmark scenarios in order matching C#/TS counterparts.
func allScenarios() []benchmarkScenario {
	var scenarios []benchmarkScenario

	// Encryption benchmarks
	scenarios = append(scenarios, encryptionScenarios()...)

	// HMAC benchmarks
	scenarios = append(scenarios, hmacScenarios()...)

	// KEX benchmarks
	scenarios = append(scenarios, kexScenarios()...)

	// Keygen benchmarks
	scenarios = append(scenarios, keygenScenarios()...)

	// Signature benchmarks
	scenarios = append(scenarios, signatureScenarios()...)

	// Protocol serialization benchmarks
	scenarios = append(scenarios, protocolSerializationScenarios()...)

	// KEX cycle benchmark
	scenarios = append(scenarios, kexCycleScenarios()...)

	// Session setup benchmarks
	scenarios = append(scenarios, sessionSetupScenarios()...)

	// Throughput benchmarks
	scenarios = append(scenarios, throughputScenarios()...)

	// Multi-channel throughput benchmark
	scenarios = append(scenarios, multiChannelScenarios()...)

	// E2E benchmarks
	scenarios = append(scenarios, e2eScenarios()...)

	return scenarios
}
