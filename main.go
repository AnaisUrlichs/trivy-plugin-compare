package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	// nolint: goimports
)

// Report represents a scan result
type Report types.Report

// Results to hold list of Result
type Results []Result

// Result holds a target and detected vulnerabilities
type Result types.Result

func Difference(a, b types.Result) (diffResult types.Result) {
	vulnOne := a.Vulnerabilities
	vulnTwo := b.Vulnerabilities

	// Loop two times, first to find Report 1 Vulnerabilities not in Report 2,
	// second loop to find Report 2 Vulnerabilities strings not in Report 1
	for i := 0; i < 2; i++ {
		// Iterate through the list of vulnerabilities in the first report
		for _, s1 := range vulnOne {
			found := false
			// Iterate through the list of vulnerabilities in the second report
			for _, s2 := range vulnTwo {
				if s1.VulnerabilityID == s2.VulnerabilityID {
					found = true
					break
				}
			}
			// String not found. We add it to the list of different vulnerabilities
			if !found {
				diffResult.Vulnerabilities = append(diffResult.Vulnerabilities, s1)
			}
		}

		// Swap the two Vulnerability Reports, only if it was the first loop
		if i == 0 {
			vulnOne, vulnTwo = vulnTwo, vulnOne
		}

	}

	return diffResult
}

// This function checks which report is older; the newer report will be modified to display the difference between both reports
func checkTimestamp(resultsOne, resultsTwo Report) (olderReport, newerReport Report) {
	if resultsOne.CreatedAt.Before(resultsTwo.CreatedAt) {
		return resultsOne, resultsTwo
	}

	return resultsTwo, resultsOne
}

func main() {

	var diffResult types.Result

	// Access the files paths provided
	filePathOne := os.Args[1]
	filePathTwo := os.Args[2]

	// Ensure both string paths provided are JSON files
	substr := ".json"

	containsOne := strings.Contains(filePathOne, substr)
	containsTwo := strings.Contains(filePathOne, substr)

	if !containsOne || !containsTwo {
		err := errors.New("the file path provided are not json files")
		fmt.Println(err)
		os.Exit(1)
	}

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

	olderReport, newerReport := checkTimestamp(resultsOne, resultsTwo)

	diffResult = Difference(olderReport.Results[0], newerReport.Results[0])

	saveResult(olderReport, newerReport, diffResult)
}

// The second report needs to be updated with the difference between both reports
func saveResult(olderReport, newerReport Report, diffResult types.Result) {

	newerReport.Results[0].Vulnerabilities = diffResult.Vulnerabilities
	newerReport.Results[0].Target = "This is the difference between image one " + newerReport.Results[0].Target + " and two " + olderReport.Results[0].Target

	o, _ := json.MarshalIndent(newerReport, "", "  ")
	_ = os.WriteFile("diff.json", o, 0644)
}
