package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
)

var resultOne types.Result
var resultTwo types.Result

var vulnOne string = `[
	{
		"VulnerabilityID": "CVE-2023-52425"
	  },
	  {
		"VulnerabilityID": "CVE-2024-28757"
	  },
	  {
		"VulnerabilityID": "CVE-2023-52426"
	  }
	]`

var vulnTwo string = `[
	{
		"VulnerabilityID": "CVE-2023-52425"
	  },
	  {
		"VulnerabilityID": "CVE-2024-28757"
	  }
	]`

func TestDifference(t *testing.T) {

	json.Unmarshal([]byte(vulnOne), &resultOne.Vulnerabilities)
	json.Unmarshal([]byte(vulnTwo), &resultTwo.Vulnerabilities)

	expectedVulnID := "CVE-2023-52426"

	diffResultIs, err := Difference(resultOne, resultTwo)

	if err != nil {
		fmt.Println("Error: \n", err)
	}

	if diffResultIs.Vulnerabilities == nil {
		t.Errorf("No differences found between reports")
	}

	vulnOutputOne := diffResultIs.Vulnerabilities

	if vulnOutputOne[0].VulnerabilityID != expectedVulnID || vulnOutputOne[0].VulnerabilityID == "" {
		t.Errorf("The result don't match between what we have %q and what we want %q", vulnOutputOne[0].VulnerabilityID, expectedVulnID)
	} else {
		fmt.Printf("The test passed \n")
	}

}
