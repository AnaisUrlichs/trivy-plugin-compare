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

	// Loop two times, first to find Report 1 Vulnerabilities not in Report 2,
	// second loop to find Report 2 Vulnerabilities strings not in Report 1
	for i := 0; i < 2; i++ {
		for _, s1 := range vulnOne {
			found := false
			for _, s2 := range vulnTwo {
				if s1.VulnerabilityID == s2.VulnerabilityID {
					found = true
					break
				}
			}
			// String not found. We add it to return Report
			if !found {
				diffResult.Vulnerabilities = append(diffResult.Vulnerabilities, s1)
			}
		}
		// Swap the two Vulnerability Reports, only if it was the first loop
		if i == 0 {
			vulnOne, vulnTwo = vulnTwo, vulnOne
		}

	}
}

func main() {

	// Access the files paths provided
	filePathOne := os.Args[1]
	filePathTwo := os.Args[2]

	// Open each file
	openFileOne, err := os.Open(filePathOne)
	openFileTwo, err := os.Open(filePathTwo)

	if err != nil {
		fmt.Println("Error: Could not open file(s)", err)
	}

	// Read everything in the file
	fileOneBytes, err := io.ReadAll(openFileOne)
	fileTwoBytes, err := io.ReadAll(openFileTwo)

	if err != nil {
		fmt.Println("Error two", err)
	}

	// Don't close the file yet
	defer openFileOne.Close()
	defer openFileTwo.Close()

	// Convert the json/bytes from the files into a valid Go struct
	var resultsOne Report
	json.Unmarshal(fileOneBytes, &resultsOne)

	var resultsTwo Report
	json.Unmarshal(fileTwoBytes, &resultsTwo)

	// Even though there is only one Results.Result array, these loops go through each array
	// and looks up the difference between the Result arrays
	for _, a := range resultsOne.Results {
		for _, b := range resultsTwo.Results {
			difference(a, b)
		}
	}

	saveResult(resultsOne, resultsTwo)
}

// The second report needs to be updated with the difference between both reports
func saveResult(resultsOne, resultsTwo Report) {
	arrlen := len(resultsTwo.Results)

	for i := 0; i < arrlen; i++ {
		resultsTwo.Results[i].Vulnerabilities = diffResult.Vulnerabilities
		resultsTwo.Results[i].Target = "This is the difference between image one " + resultsTwo.Results[i].Target + " and two " + resultsOne.Results[i].Target
	}

	o, _ := json.MarshalIndent(resultsTwo, "", "  ")
	_ = os.WriteFile("diff.json", o, 0644)

}
