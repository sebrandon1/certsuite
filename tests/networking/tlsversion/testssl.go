// Copyright (C) 2024-2026 Red Hat, Inc.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package tlsversion

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redhat-best-practices-for-k8s/certsuite/internal/clientsholder"
)

// testSSLFinding represents a single finding from testssl.sh --jsonfile output.
type testSSLFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
}

// testSSLResult holds the parsed testssl.sh scan results for a single endpoint.
type testSSLResult struct {
	OfferedVersions map[uint16]bool
	OfferedCiphers  []string // OpenSSL-style cipher names from TLS 1.2
	IsTLS           bool
	Reachable       bool
}

// testssl.sh uses these IDs for TLS protocol version checks.
var testSSLProtocolIDs = map[string]uint16{
	"sslv2":  versionDisallowed,
	"sslv3":  versionDisallowed,
	"tls1":   tls.VersionTLS10,
	"tls1_1": tls.VersionTLS11,
	"tls1_2": tls.VersionTLS12,
	"tls1_3": tls.VersionTLS13,
}

const (
	cipherFindingSubmatchCount = 2
	testSSLExecTimeout         = 3 * time.Minute
	versionDisallowed          = 0

	probeMethodOpenSSL = "openssl"
	probeMethodTestSSL = "testssl"
)

var cipherFindingRegex = regexp.MustCompile(`TLS \d\.\d\s+\S+\s+(\S+)`)

// ProbeServicePortViaTestSSL runs testssl.sh inside a probe pod against the
// given endpoint and evaluates TLS compliance against the policy.
func ProbeServicePortViaTestSSL(ch clientsholder.Command, ctx clientsholder.Context, address string, port int32, policy TLSPolicy) TLSProbeResult {
	endpoint := net.JoinHostPort(address, strconv.Itoa(int(port)))

	cmd := fmt.Sprintf(
		"f=/tmp/testssl-$$.json;"+
			" testssl.sh --jsonfile \"$f\" --quiet --color 0"+
			" --warnings off --sneaky --fast --connect-timeout 5 --openssl-timeout 5"+
			" --protocols %s >/dev/null 2>&1;"+
			" cat \"$f\" 2>/dev/null;"+
			" rm -f \"$f\"", endpoint)
	stdout, _, err := ch.ExecCommandContainerWithTimeout(ctx, cmd, testSSLExecTimeout)

	if err != nil && strings.TrimSpace(stdout) == "" {
		return TLSProbeResult{
			Compliant: true,
			IsTLS:     false,
			Reachable: false,
			Reason:    fmt.Sprintf("testssl.sh probe failed: %v", err),
		}
	}

	result, parseErr := parseTestSSLJSON(stdout)
	if parseErr != nil {
		return TLSProbeResult{
			Compliant: true,
			IsTLS:     false,
			Reachable: false,
			Reason:    fmt.Sprintf("failed to parse testssl.sh output: %v", parseErr),
		}
	}

	if !result.Reachable {
		return TLSProbeResult{
			Compliant: true,
			IsTLS:     false,
			Reachable: false,
			Reason:    "port unreachable (via testssl.sh)",
		}
	}

	if !result.IsTLS {
		return TLSProbeResult{
			Compliant: true,
			IsTLS:     false,
			Reachable: true,
			Reason:    "non-TLS service (informational, via testssl.sh)",
		}
	}

	return evaluateTestSSLCompliance(result, policy)
}

// parseTestSSLJSON parses the flat JSON array output from testssl.sh --jsonfile.
func parseTestSSLJSON(jsonOutput string) (*testSSLResult, error) {
	jsonOutput = strings.TrimSpace(jsonOutput)
	if jsonOutput == "" {
		return nil, fmt.Errorf("empty testssl.sh output")
	}

	var findings []testSSLFinding
	if err := json.Unmarshal([]byte(jsonOutput), &findings); err != nil {
		return nil, fmt.Errorf("JSON unmarshal: %w", err)
	}

	result := &testSSLResult{
		OfferedVersions: make(map[uint16]bool),
		Reachable:       true,
	}

	if len(findings) == 0 {
		result.Reachable = false
		return result, nil
	}

	for _, f := range findings {
		if f.ID == "scanProblem" || f.ID == "connect_timeout" {
			if strings.Contains(f.Finding, "refused") || strings.Contains(f.Finding, "timeout") || strings.Contains(f.Finding, "unreachable") {
				result.Reachable = false
				return result, nil
			}
		}

		lowerID := strings.ToLower(f.ID)

		if ver, ok := testSSLProtocolIDs[lowerID]; ok {
			if strings.HasPrefix(strings.ToLower(f.Finding), "offered") {
				if ver != versionDisallowed {
					result.OfferedVersions[ver] = true
					result.IsTLS = true
				}
			}
			continue
		}

		if strings.HasPrefix(lowerID, "cipher-tls1_2") || strings.HasPrefix(lowerID, "cipher_tls1_2") {
			cipherName := extractTestSSLCipherName(f.Finding)
			if cipherName != "" {
				result.OfferedCiphers = append(result.OfferedCiphers, cipherName)
				result.IsTLS = true
			}
		}
	}

	return result, nil
}

// extractTestSSLCipherName extracts the cipher suite name from a testssl.sh cipher finding.
// Format: "TLS 1.2 xc02c ECDHE-ECDSA-AES256-GCM-SHA384 ECDH 256 AESGCM 256"
func extractTestSSLCipherName(finding string) string {
	matches := cipherFindingRegex.FindStringSubmatch(finding)
	if len(matches) >= cipherFindingSubmatchCount {
		return matches[1]
	}
	return ""
}

// evaluateTestSSLCompliance checks the testssl.sh scan result against the TLS policy.
// It mirrors the four-step logic of the openssl exec probe:
//  1. Minimum version must be offered
//  2. No versions below minimum should be offered
//  3. All versions above minimum through TLS 1.3 must be offered
//  4. No disallowed ciphers should be offered (TLS 1.2 only)
func evaluateTestSSLCompliance(result *testSSLResult, policy TLSPolicy) TLSProbeResult {
	if r := checkTestSSLVersionCompliance(result, policy); r != nil {
		return *r
	}

	if r := checkTestSSLCipherCompliance(result, policy); r != nil {
		return *r
	}

	return TLSProbeResult{
		Compliant:     true,
		IsTLS:         true,
		Reachable:     true,
		NegotiatedVer: offeredVersionsString(result),
		Reason:        fmt.Sprintf("server honors %s profile (via testssl.sh)", policy.ProfileType),
	}
}

func checkTestSSLVersionCompliance(result *testSSLResult, policy TLSPolicy) *TLSProbeResult {
	// Step 1: Minimum version must be offered
	if !result.OfferedVersions[policy.MinTLSVersion] {
		return &TLSProbeResult{
			Compliant:     false,
			IsTLS:         true,
			Reachable:     true,
			NegotiatedVer: offeredVersionsString(result),
			Reason:        fmt.Sprintf("server does not support %s (via testssl.sh)", tlsVersionString(policy.MinTLSVersion)),
		}
	}

	// Step 2: No versions below minimum should be offered
	belowVer := versionBelow(policy.MinTLSVersion)
	if belowVer > 0 && result.OfferedVersions[belowVer] {
		return &TLSProbeResult{
			Compliant:     false,
			IsTLS:         true,
			Reachable:     true,
			NegotiatedVer: offeredVersionsString(result),
			Reason:        fmt.Sprintf("server accepts %s (%s minimum required, via testssl.sh)", tlsVersionString(belowVer), tlsVersionString(policy.MinTLSVersion)),
		}
	}

	// Step 3: All versions above minimum through TLS 1.3 must be offered
	for _, aboveVer := range versionsAbove(policy.MinTLSVersion) {
		if !result.OfferedVersions[aboveVer] {
			return &TLSProbeResult{
				Compliant:     false,
				IsTLS:         true,
				Reachable:     true,
				NegotiatedVer: offeredVersionsString(result),
				Reason: fmt.Sprintf("server rejected %s but %s profile requires support for versions %s through TLS 1.3 (via testssl.sh)",
					tlsVersionString(aboveVer), policy.ProfileType, tlsVersionString(policy.MinTLSVersion)),
			}
		}
	}

	return nil
}

func checkTestSSLCipherCompliance(result *testSSLResult, policy TLSPolicy) *TLSProbeResult {
	if policy.MinTLSVersion > tls.VersionTLS12 || len(result.OfferedCiphers) == 0 {
		return nil
	}

	disallowed := computeDisallowedOpenSSLCiphers(policy)
	disallowedSet := make(map[string]bool, len(disallowed))
	for _, name := range disallowed {
		disallowedSet[name] = true
	}

	for _, cipher := range result.OfferedCiphers {
		if disallowedSet[cipher] {
			return &TLSProbeResult{
				Compliant:     false,
				IsTLS:         true,
				Reachable:     true,
				NegotiatedVer: offeredVersionsString(result),
				Reason:        fmt.Sprintf("server accepted disallowed cipher %s (not in %s profile, via testssl.sh)", cipher, policy.ProfileType),
			}
		}
	}

	return nil
}

// offeredVersionsString returns a human-readable string of offered TLS versions.
func offeredVersionsString(result *testSSLResult) string {
	allVersions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	var offered []string
	for _, v := range allVersions {
		if result.OfferedVersions[v] {
			offered = append(offered, tlsVersionString(v))
		}
	}
	if len(offered) == 0 {
		return "none"
	}
	return strings.Join(offered, ", ")
}
