package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
)

var diffResultIs types.Result
var a types.Result
var b types.Result

var vulnOne string = `[
	{
		"VulnerabilityID": "CVE-2023-52425",
		"PkgID": "libexpat@2.5.0-r0",
		"PkgName": "libexpat",
		"PkgIdentifier": {
		  "PURL": "pkg:apk/alpine/libexpat@2.5.0-r0?arch=aarch64\u0026distro=3.17.7"
		},
		"InstalledVersion": "2.5.0-r0",
		"FixedVersion": "2.6.0-r0",
		"Status": "fixed",
		"Layer": {
		  "Digest": "sha256:3c20cd9499e8b2e645084657bd63cbcbc76dbc0d98ecbd466d0dde5fa1c80ab1",
		  "DiffID": "sha256:a63c45f9eecdea9445b7ca3a154feeaac3c0872835aec2208c54764aee3580b9"
		},
		"SeveritySource": "nvd",
		"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-52425",
		"DataSource": {
		  "ID": "alpine",
		  "Name": "Alpine Secdb",
		  "URL": "https://secdb.alpinelinux.org/"
		},
		"Title": "expat: parsing large tokens can trigger a denial of service",
		"Description": "libexpat through 2.5.0 allows a denial of service (resource consumption) because many full reparsings are required in the case of a large token for which multiple buffer fills are needed.",
		"Severity": "HIGH",
		"CweIDs": [
		  "CWE-400"
		],
		"VendorSeverity": {
		  "nvd": 3,
		  "oracle-oval": 2,
		  "photon": 3,
		  "redhat": 2,
		  "ubuntu": 2
		},
		"CVSS": {
		  "nvd": {
			"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			"V3Score": 7.5
		  },
		  "redhat": {
			"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			"V3Score": 7.5
		  }
		},
		"References": [
		],
		"PublishedDate": "2024-02-04T20:15:46.063Z",
		"LastModifiedDate": "2024-02-26T16:27:48.367Z"
	  },
	  {
		"VulnerabilityID": "CVE-2024-28757",
		"PkgID": "libexpat@2.5.0-r0",
		"PkgName": "libexpat",
		"PkgIdentifier": {
		  "PURL": "pkg:apk/alpine/libexpat@2.5.0-r0?arch=aarch64\u0026distro=3.17.7"
		},
		"InstalledVersion": "2.5.0-r0",
		"FixedVersion": "2.6.2-r0",
		"Status": "fixed",
		"Layer": {
		  "Digest": "sha256:3c20cd9499e8b2e645084657bd63cbcbc76dbc0d98ecbd466d0dde5fa1c80ab1",
		  "DiffID": "sha256:a63c45f9eecdea9445b7ca3a154feeaac3c0872835aec2208c54764aee3580b9"
		},
		"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28757",
		"DataSource": {
		  "ID": "alpine",
		  "Name": "Alpine Secdb",
		  "URL": "https://secdb.alpinelinux.org/"
		},
		"Title": "expat: XML Entity Expansion",
		"Description": "libexpat through 2.6.1 allows an XML Entity Expansion attack when there is isolated use of external parsers (created via XML_ExternalEntityParserCreate).",
		"Severity": "HIGH",
		"VendorSeverity": {
		  "amazon": 3,
		  "oracle-oval": 2,
		  "photon": 3,
		  "redhat": 2,
		  "ubuntu": 2
		},
		"CVSS": {
		  "redhat": {
			"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			"V3Score": 7.5
		  }
		},
		"References": [
		],
		"PublishedDate": "2024-03-10T05:15:06.57Z",
		"LastModifiedDate": "2024-03-23T03:15:11.92Z"
	  },
	  {
		"VulnerabilityID": "CVE-2023-52426",
		"PkgID": "libexpat@2.5.0-r0",
		"PkgName": "libexpat",
		"PkgIdentifier": {
		  "PURL": "pkg:apk/alpine/libexpat@2.5.0-r0?arch=aarch64\u0026distro=3.17.7"
		},
		"InstalledVersion": "2.5.0-r0",
		"FixedVersion": "2.6.0-r0",
		"Status": "fixed",
		"Layer": {
		  "Digest": "sha256:3c20cd9499e8b2e645084657bd63cbcbc76dbc0d98ecbd466d0dde5fa1c80ab1",
		  "DiffID": "sha256:a63c45f9eecdea9445b7ca3a154feeaac3c0872835aec2208c54764aee3580b9"
		},
		"SeveritySource": "nvd",
		"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-52426",
		"DataSource": {
		  "ID": "alpine",
		  "Name": "Alpine Secdb",
		  "URL": "https://secdb.alpinelinux.org/"
		},
		"Title": "expat: recursive XML entity expansion vulnerability",
		"Description": "libexpat through 2.5.0 allows recursive XML Entity Expansion if XML_DTD is undefined at compile time.",
		"Severity": "MEDIUM",
		"CweIDs": [
		  "CWE-776"
		],
		"VendorSeverity": {
		  "amazon": 2,
		  "cbl-mariner": 2,
		  "nvd": 2,
		  "photon": 2,
		  "redhat": 2
		},
		"CVSS": {
		  "nvd": {
			"V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
			"V3Score": 5.5
		  },
		  "redhat": {
			"V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
			"V3Score": 5.5
		  }
		},
		"References": [
		],
		"PublishedDate": "2024-02-04T20:15:46.12Z",
		"LastModifiedDate": "2024-03-07T17:15:11.893Z"
	  }
	]`

var vulnTwo string = `[
	{
		"VulnerabilityID": "CVE-2023-52425",
		"PkgID": "libexpat@2.5.0-r0",
		"PkgName": "libexpat",
		"PkgIdentifier": {
		  "PURL": "pkg:apk/alpine/libexpat@2.5.0-r0?arch=aarch64\u0026distro=3.17.7"
		},
		"InstalledVersion": "2.5.0-r0",
		"FixedVersion": "2.6.0-r0",
		"Status": "fixed",
		"Layer": {
		  "Digest": "sha256:3c20cd9499e8b2e645084657bd63cbcbc76dbc0d98ecbd466d0dde5fa1c80ab1",
		  "DiffID": "sha256:a63c45f9eecdea9445b7ca3a154feeaac3c0872835aec2208c54764aee3580b9"
		},
		"SeveritySource": "nvd",
		"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-52425",
		"DataSource": {
		  "ID": "alpine",
		  "Name": "Alpine Secdb",
		  "URL": "https://secdb.alpinelinux.org/"
		},
		"Title": "expat: parsing large tokens can trigger a denial of service",
		"Description": "libexpat through 2.5.0 allows a denial of service (resource consumption) because many full reparsings are required in the case of a large token for which multiple buffer fills are needed.",
		"Severity": "HIGH",
		"CweIDs": [
		  "CWE-400"
		],
		"VendorSeverity": {
		  "nvd": 3,
		  "oracle-oval": 2,
		  "photon": 3,
		  "redhat": 2,
		  "ubuntu": 2
		},
		"CVSS": {
		  "nvd": {
			"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			"V3Score": 7.5
		  },
		  "redhat": {
			"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			"V3Score": 7.5
		  }
		},
		"References": [
		],
		"PublishedDate": "2024-02-04T20:15:46.063Z",
		"LastModifiedDate": "2024-02-26T16:27:48.367Z"
	  },
	  {
		"VulnerabilityID": "CVE-2024-28757",
		"PkgID": "libexpat@2.5.0-r0",
		"PkgName": "libexpat",
		"PkgIdentifier": {
		  "PURL": "pkg:apk/alpine/libexpat@2.5.0-r0?arch=aarch64\u0026distro=3.17.7"
		},
		"InstalledVersion": "2.5.0-r0",
		"FixedVersion": "2.6.2-r0",
		"Status": "fixed",
		"Layer": {
		  "Digest": "sha256:3c20cd9499e8b2e645084657bd63cbcbc76dbc0d98ecbd466d0dde5fa1c80ab1",
		  "DiffID": "sha256:a63c45f9eecdea9445b7ca3a154feeaac3c0872835aec2208c54764aee3580b9"
		},
		"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-28757",
		"DataSource": {
		  "ID": "alpine",
		  "Name": "Alpine Secdb",
		  "URL": "https://secdb.alpinelinux.org/"
		},
		"Title": "expat: XML Entity Expansion",
		"Description": "libexpat through 2.6.1 allows an XML Entity Expansion attack when there is isolated use of external parsers (created via XML_ExternalEntityParserCreate).",
		"Severity": "HIGH",
		"VendorSeverity": {
		  "amazon": 3,
		  "oracle-oval": 2,
		  "photon": 3,
		  "redhat": 2,
		  "ubuntu": 2
		},
		"CVSS": {
		  "redhat": {
			"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			"V3Score": 7.5
		  }
		},
		"References": [
		],
		"PublishedDate": "2024-03-10T05:15:06.57Z",
		"LastModifiedDate": "2024-03-23T03:15:11.92Z"
	  }
	]`

func TestDifference(t *testing.T) {

	json.Unmarshal([]byte(vulnOne), &a.Vulnerabilities)
	json.Unmarshal([]byte(vulnTwo), &b.Vulnerabilities)

	expectedVulnID := "CVE-2023-52426"

	diffResultIs = Difference(a, b)

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
