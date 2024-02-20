package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/aquasecurity/trivy/pkg/types"
	// nolint: goimports
)

// Report represents a scan result
type Report types.Report

// Results to hold list of Result
type Results []Result

// Result holds a target and detected vulnerabilities
type Result types.Result

var diffResult types.Result

func difference(a, b types.Result) {
	vulnOne := a.Vulnerabilities
	vulnTwo := b.Vulnerabilities

	// Loop two times, first to find slice1 strings not in slice2,
	// second loop to find slice2 strings not in slice1
	for i := 0; i < 2; i++ {
		for _, s1 := range vulnOne {
			found := false
			for _, s2 := range vulnTwo {
				if s1.VulnerabilityID == s2.VulnerabilityID {
					found = true
					break
				}
			}
			// String not found. We add it to return slice
			if !found {
				diffResult.Vulnerabilities = append(diffResult.Vulnerabilities, s1)
			}
		}
		// Swap the slices, only if it was the first loop
		if i == 0 {
			vulnOne, vulnTwo = vulnTwo, vulnOne
		}

	}
}

func main() {

	filePathOne := os.Args[1]
	filePathTwo := os.Args[2]

	openFileOne, err := os.Open(filePathOne)
	openFileTwo, err := os.Open(filePathTwo)

	if err != nil {
		fmt.Println("Error one", err)
	}

	fileOneBytes, err := io.ReadAll(openFileOne)
	fileTwoBytes, err := io.ReadAll(openFileTwo)

	if err != nil {
		fmt.Println("Error two", err)
	}

	defer openFileOne.Close()
	defer openFileTwo.Close()

	var resultsOne Report
	json.Unmarshal(fileOneBytes, &resultsOne)

	var resultsTwo Report
	json.Unmarshal(fileTwoBytes, &resultsTwo)

	for _, a := range resultsOne.Results {
		for _, b := range resultsTwo.Results {
			difference(a, b)
		}
	}

	arrlen := len(resultsTwo.Results)

	for i := 0; i < arrlen; i++ {
		resultsTwo.Results[i] = diffResult
	}

	o, _ := json.MarshalIndent(resultsTwo, "", "  ")
	_ = os.WriteFile("test.json", o, 0644)
	fmt.Printf(string(o))
}
