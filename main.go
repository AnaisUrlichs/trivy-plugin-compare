package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
)

// Report represents a scan result
type Report types.Report

// Results to hold list of Result
type Results []Result

// Result holds a target and detected vulnerabilities
type Result types.Result

// function comparing two Trivy scan results to identify differences in Vulnerabilities
func Difference(a, b types.Result) (diffResult types.Result, err error) {
	vulnOne := a.Vulnerabilities
	vulnTwo := b.Vulnerabilities

	if vulnOne == nil || vulnTwo == nil {
		err = errors.New("something went wrong accessign the vulnerabilities")
		return diffResult, err
	}

	mpOne := make(map[string]bool)
	mpTwo := make(map[string]bool)

	// first, go through each vulnerability in the first report and add the ID to the map
	for _, s1 := range vulnOne {
		mpOne[s1.VulnerabilityID] = true
	}

	// next, go through each vulnerability in the second report
	for _, s2 := range vulnTwo {

		// if the vulnerability does not exist in the first report, add it to the results
		// this works for cases in which the second report is longer than the first
		if _, y := mpOne[s2.VulnerabilityID]; !y {
			diffResult.Vulnerabilities = append(diffResult.Vulnerabilities, s2)
		}

		// add rach vulnerability from the second report to a separate map
		mpTwo[s2.VulnerabilityID] = true
	}

	// lastly, check whether the vulnerabilities from the first report are all present in the second report
	for _, s1 := range vulnOne {
		// if a vulnerability is in the first report but not in the second, add it to the results
		// this is necessary for cases where the first report is longer than the second report
		if _, y := mpTwo[s1.VulnerabilityID]; !y {
			diffResult.Vulnerabilities = append(diffResult.Vulnerabilities, s1)
		}
	}

	return diffResult, nil
}

// This function checks which report is older; the newer report will be modified to display the difference between both reports
func checkTimestamp(resultsOne, resultsTwo Report) (olderReport, newerReport Report, err error) {
	if resultsOne.CreatedAt.Before(resultsTwo.CreatedAt) {
		return resultsOne, resultsTwo, nil
	}

	return resultsTwo, resultsOne, nil
}

// The second report needs to be updated with the difference between both reports
func saveResult(olderReport, newerReport Report, diffResult types.Result) {

	newerReport.Results[0].Vulnerabilities = diffResult.Vulnerabilities
	newerReport.Results[0].Target = "This is the difference between image one " + newerReport.Results[0].Target + " and two " + olderReport.Results[0].Target

	o, _ := json.MarshalIndent(newerReport, "", "  ")
	_ = os.WriteFile("diff.json", o, 0644)
}

func main() {

	if len(os.Args) <= 2 {
		err := errors.New("no arguments or not enough provided")
		fmt.Println(err)
		os.Exit(1)
	}

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
	openFileOne, errOne := os.Open(filePathOne)
	openFileTwo, errTwo := os.Open(filePathTwo)

	if errOne != nil || errTwo != nil {
		fmt.Println("Error: Could not open file(s) \n", errOne, errTwo)
		os.Exit(1)
	}

	// Read everything in the file
	fileOneBytes, errOne := io.ReadAll(openFileOne)
	fileTwoBytes, errTwo := io.ReadAll(openFileTwo)

	if errOne != nil || errTwo != nil {
		fmt.Println("Error: Could not read the file \n", errOne, errTwo)
		os.Exit(1)
	}

	// Don't close the file yet
	defer openFileOne.Close()
	defer openFileTwo.Close()

	// Convert the json/bytes from the files into a valid Go struct
	var resultsOne Report
	json.Unmarshal(fileOneBytes, &resultsOne)

	var resultsTwo Report
	json.Unmarshal(fileTwoBytes, &resultsTwo)

	olderReport, newerReport, err := checkTimestamp(resultsOne, resultsTwo)

	if err != nil {
		fmt.Println("Error: \n", err)
	}

	diffResult, err := Difference(olderReport.Results[0], newerReport.Results[0])

	if err != nil {
		fmt.Println("Error: \n", err)
	}

	saveResult(olderReport, newerReport, diffResult)
}
