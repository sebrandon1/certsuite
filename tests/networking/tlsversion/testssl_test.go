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
	"testing"

	"github.com/redhat-best-practices-for-k8s/certsuite/internal/clientsholder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildTestSSLJSON(findings []testSSLFinding) string {
	data, _ := json.Marshal(findings)
	return string(data)
}

func TestParseTestSSLJSON_TLS12And13(t *testing.T) {
	jsonStr := buildTestSSLJSON([]testSSLFinding{
		{ID: "TLS1_2", Finding: "offered", Severity: "OK"},
		{ID: "TLS1_3", Finding: "offered", Severity: "OK"},
		{ID: "TLS1_1", Finding: "not offered", Severity: "OK"},
		{ID: "TLS1", Finding: "not offered", Severity: "OK"},
		{ID: "SSLv3", Finding: "not offered", Severity: "OK"},
		{ID: "SSLv2", Finding: "not offered", Severity: "OK"},
		{ID: "cipher-tls1_2_x01", Finding: "TLS 1.2 xc02f ECDHE-RSA-AES128-GCM-SHA256 ECDH 256 AESGCM 128", Severity: "OK"},
		{ID: "cipher-tls1_2_x02", Finding: "TLS 1.2 xc030 ECDHE-RSA-AES256-GCM-SHA384 ECDH 256 AESGCM 256", Severity: "OK"},
	})

	result, err := parseTestSSLJSON(jsonStr)
	require.NoError(t, err)
	assert.True(t, result.IsTLS)
	assert.True(t, result.Reachable)
	assert.True(t, result.OfferedVersions[tls.VersionTLS12])
	assert.True(t, result.OfferedVersions[tls.VersionTLS13])
	assert.False(t, result.OfferedVersions[tls.VersionTLS11])
	assert.False(t, result.OfferedVersions[tls.VersionTLS10])
	assert.Len(t, result.OfferedCiphers, 2)
	assert.Contains(t, result.OfferedCiphers, "ECDHE-RSA-AES128-GCM-SHA256")
	assert.Contains(t, result.OfferedCiphers, "ECDHE-RSA-AES256-GCM-SHA384")
}

func TestParseTestSSLJSON_TLS12Only(t *testing.T) {
	jsonStr := buildTestSSLJSON([]testSSLFinding{
		{ID: "TLS1_2", Finding: "offered", Severity: "OK"},
		{ID: "TLS1_3", Finding: "not offered", Severity: "INFO"},
		{ID: "cipher-tls1_2_x01", Finding: "TLS 1.2 xc02f ECDHE-RSA-AES128-GCM-SHA256 ECDH 256 AESGCM 128", Severity: "OK"},
	})

	result, err := parseTestSSLJSON(jsonStr)
	require.NoError(t, err)
	assert.True(t, result.OfferedVersions[tls.VersionTLS12])
	assert.False(t, result.OfferedVersions[tls.VersionTLS13])
}

func TestParseTestSSLJSON_TLS13Only(t *testing.T) {
	jsonStr := buildTestSSLJSON([]testSSLFinding{
		{ID: "TLS1_2", Finding: "not offered", Severity: "INFO"},
		{ID: "TLS1_3", Finding: "offered", Severity: "OK"},
	})

	result, err := parseTestSSLJSON(jsonStr)
	require.NoError(t, err)
	assert.False(t, result.OfferedVersions[tls.VersionTLS12])
	assert.True(t, result.OfferedVersions[tls.VersionTLS13])
}

func TestParseTestSSLJSON_Empty(t *testing.T) {
	_, err := parseTestSSLJSON("")
	assert.Error(t, err)
}

func TestParseTestSSLJSON_EmptyArray(t *testing.T) {
	result, err := parseTestSSLJSON("[]")
	require.NoError(t, err)
	assert.False(t, result.Reachable)
}

func TestParseTestSSLJSON_InvalidJSON(t *testing.T) {
	_, err := parseTestSSLJSON("{not json}")
	assert.Error(t, err)
}

func TestParseTestSSLJSON_Unreachable(t *testing.T) {
	jsonStr := buildTestSSLJSON([]testSSLFinding{
		{ID: "scanProblem", Finding: "connection refused", Severity: "WARN"},
	})

	result, err := parseTestSSLJSON(jsonStr)
	require.NoError(t, err)
	assert.False(t, result.Reachable)
}

func TestEvaluateTestSSLCompliance_Intermediate_TLS12And13(t *testing.T) {
	result := &testSSLResult{
		OfferedVersions: map[uint16]bool{
			tls.VersionTLS12: true,
			tls.VersionTLS13: true,
		},
		OfferedCiphers: []string{
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES256-GCM-SHA384",
		},
		IsTLS:     true,
		Reachable: true,
	}

	probe := evaluateTestSSLCompliance(result, intermediatePolicy())
	assert.True(t, probe.Compliant)
	assert.Contains(t, probe.Reason, "testssl.sh")
}

func TestEvaluateTestSSLCompliance_Intermediate_TLS12Only(t *testing.T) {
	result := &testSSLResult{
		OfferedVersions: map[uint16]bool{
			tls.VersionTLS12: true,
		},
		IsTLS:     true,
		Reachable: true,
	}

	probe := evaluateTestSSLCompliance(result, intermediatePolicy())
	assert.False(t, probe.Compliant)
	assert.Contains(t, probe.Reason, "rejected TLS 1.3")
}

func TestEvaluateTestSSLCompliance_Intermediate_TLS13Only(t *testing.T) {
	result := &testSSLResult{
		OfferedVersions: map[uint16]bool{
			tls.VersionTLS13: true,
		},
		IsTLS:     true,
		Reachable: true,
	}

	probe := evaluateTestSSLCompliance(result, intermediatePolicy())
	assert.False(t, probe.Compliant)
	assert.Contains(t, probe.Reason, "does not support TLS 1.2")
}

func TestEvaluateTestSSLCompliance_Modern_TLS13Only(t *testing.T) {
	result := &testSSLResult{
		OfferedVersions: map[uint16]bool{
			tls.VersionTLS13: true,
		},
		IsTLS:     true,
		Reachable: true,
	}

	probe := evaluateTestSSLCompliance(result, modernPolicy())
	assert.True(t, probe.Compliant)
}

func TestEvaluateTestSSLCompliance_Modern_TLS12Offered(t *testing.T) {
	result := &testSSLResult{
		OfferedVersions: map[uint16]bool{
			tls.VersionTLS12: true,
			tls.VersionTLS13: true,
		},
		IsTLS:     true,
		Reachable: true,
	}

	probe := evaluateTestSSLCompliance(result, modernPolicy())
	assert.False(t, probe.Compliant)
	assert.Contains(t, probe.Reason, "accepts TLS 1.2")
}

func TestEvaluateTestSSLCompliance_DisallowedCipher(t *testing.T) {
	result := &testSSLResult{
		OfferedVersions: map[uint16]bool{
			tls.VersionTLS12: true,
			tls.VersionTLS13: true,
		},
		OfferedCiphers: []string{
			"ECDHE-RSA-AES128-GCM-SHA256",
			"DES-CBC3-SHA", // not in Intermediate profile
		},
		IsTLS:     true,
		Reachable: true,
	}

	probe := evaluateTestSSLCompliance(result, intermediatePolicy())
	assert.False(t, probe.Compliant)
	assert.Contains(t, probe.Reason, "disallowed cipher")
	assert.Contains(t, probe.Reason, "DES-CBC3-SHA")
}

func TestExtractTestSSLCipherName(t *testing.T) {
	tests := []struct {
		name     string
		finding  string
		expected string
	}{
		{
			name:     "standard format",
			finding:  "TLS 1.2 xc02f ECDHE-RSA-AES128-GCM-SHA256 ECDH 256 AESGCM 128",
			expected: "ECDHE-RSA-AES128-GCM-SHA256",
		},
		{
			name:     "TLS 1.3 cipher",
			finding:  "TLS 1.3 x1301 TLS_AES_128_GCM_SHA256 ECDH/MLKEM AESGCM 128",
			expected: "TLS_AES_128_GCM_SHA256",
		},
		{
			name:     "empty",
			finding:  "",
			expected: "",
		},
		{
			name:     "no match",
			finding:  "some unrelated text",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTestSSLCipherName(tt.finding)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestOfferedVersionsString(t *testing.T) {
	tests := []struct {
		name     string
		versions map[uint16]bool
		expected string
	}{
		{
			name:     "TLS 1.2 and 1.3",
			versions: map[uint16]bool{tls.VersionTLS12: true, tls.VersionTLS13: true},
			expected: "TLS 1.2, TLS 1.3",
		},
		{
			name:     "TLS 1.3 only",
			versions: map[uint16]bool{tls.VersionTLS13: true},
			expected: "TLS 1.3",
		},
		{
			name:     "empty",
			versions: map[uint16]bool{},
			expected: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &testSSLResult{OfferedVersions: tt.versions}
			got := offeredVersionsString(result)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestProbeServicePortViaTestSSL_ExecFailure(t *testing.T) {
	mock := newMockCommand(
		mockPattern{"testssl.sh", mockExecResult{stdout: "", err: assert.AnError}},
	)

	result := ProbeServicePortViaTestSSL(mock, clientsholder.NewContext("ns", "pod", "container"), "10.0.0.1", 443, intermediatePolicy())
	assert.True(t, result.Compliant)
	assert.False(t, result.IsTLS)
	assert.False(t, result.Reachable)
}

func TestProbeServicePortViaTestSSL_Compliant(t *testing.T) {
	findings := buildTestSSLJSON([]testSSLFinding{
		{ID: "TLS1_2", Finding: "offered", Severity: "OK"},
		{ID: "TLS1_3", Finding: "offered", Severity: "OK"},
		{ID: "cipher-tls1_2_x01", Finding: "TLS 1.2 xc02f ECDHE-RSA-AES128-GCM-SHA256 ECDH 256 AESGCM 128", Severity: "OK"},
	})

	mock := newMockCommand(
		mockPattern{"testssl.sh", mockExecResult{stdout: findings}},
	)

	result := ProbeServicePortViaTestSSL(mock, clientsholder.NewContext("ns", "pod", "container"), "10.0.0.1", 443, intermediatePolicy())
	assert.True(t, result.Compliant)
	assert.True(t, result.IsTLS)
	assert.True(t, result.Reachable)
}

func TestProbeServicePortViaTestSSL_NonCompliant(t *testing.T) {
	findings := buildTestSSLJSON([]testSSLFinding{
		{ID: "TLS1_2", Finding: "offered", Severity: "OK"},
		{ID: "TLS1_3", Finding: "not offered", Severity: "INFO"},
	})

	mock := newMockCommand(
		mockPattern{"testssl.sh", mockExecResult{stdout: findings}},
	)

	result := ProbeServicePortViaTestSSL(mock, clientsholder.NewContext("ns", "pod", "container"), "10.0.0.1", 443, intermediatePolicy())
	assert.False(t, result.Compliant)
	assert.Contains(t, result.Reason, "rejected TLS 1.3")
}
