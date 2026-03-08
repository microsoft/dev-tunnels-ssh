// Copyright (c) Microsoft Corporation. All rights reserved.

package main

// JSON output types matching bench/common/schema.json

type metadata struct {
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platformVersion"`
	OS              string `json:"os"`
	Timestamp       string `json:"timestamp"`
	RunCount        int    `json:"runCount"`
	GitCommit       string `json:"gitCommit"`
}

type metric struct {
	Name           string    `json:"name"`
	Unit           string    `json:"unit"`
	Values         []float64 `json:"values"`
	HigherIsBetter bool      `json:"higherIsBetter"`
}

type verification struct {
	Passed bool   `json:"passed"`
	Error  string `json:"error,omitempty"`
}

type suite struct {
	Category     string            `json:"category"`
	Name         string            `json:"name"`
	Tags         map[string]string `json:"tags"`
	Metrics      []metric          `json:"metrics"`
	Verification *verification     `json:"verification,omitempty"`
}

type benchmarkResults struct {
	Metadata metadata `json:"metadata"`
	Suites   []suite  `json:"suites"`
}

// benchmarkScenario defines a single benchmark to run.
type benchmarkScenario struct {
	name     string
	category string
	tags     map[string]string
	run      func(runs int) []metric
	verify   func() error // optional correctness check; nil means no verification
}
