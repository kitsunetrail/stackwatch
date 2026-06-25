package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
)

var genTime = time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)

// sampleReport builds a report exercising every section.
func sampleReport() analyze.Report {
	scans := []scanner.ImageScan{
		{
			Image:  "web:1.0",
			OSEOSL: true,
			Findings: []scanner.Finding{
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
				{Image: "web:1.0", Class: scanner.ClassLang, Package: "setuptools", InstalledVer: "53.0.0", FixedVer: "78.1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2"},
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "e2fsprogs", InstalledVer: "1.44", FixedVer: "", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-3"},
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "gcc-8-base", InstalledVer: "8.3", FixedVer: "", Status: scanner.StatusWontFix, Severity: scanner.SeverityHigh, VulnID: "CVE-4"},
			},
		},
		{Image: "broken:1", Err: errString("pull failed")},
	}
	return analyze.Build(scans, genTime)
}

type errString string

func (e errString) Error() string { return string(e) }

func TestFormatSlackText_Sections(t *testing.T) {
	out := FormatSlackText(sampleReport())

	mustContain := []string{
		"StackWatch",
		"2026-06-24",
		"web:1.0",
		"libc-bin",
		"2.28-10 → 2.28-10+deb10u2",
		"setuptools",
		"Distro security update", // OS distro_update label
		"Needs care",             // lang caution label
		"end-of-life",            // EOSL
		"e2fsprogs",  // affected
		"gcc-8-base", // wont_fix
		"broken:1",   // scan error
		"pull failed",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n---\n%s", s, out)
		}
	}
}

func TestFormatSlackText_Ordering(t *testing.T) {
	out := FormatSlackText(sampleReport())
	eosl := strings.Index(out, "end-of-life")
	actionable := strings.Index(out, "libc-bin")
	affected := strings.Index(out, "e2fsprogs")
	wontfix := strings.Index(out, "gcc-8-base")

	if !(eosl < actionable && actionable < affected && affected < wontfix) {
		t.Errorf("section order wrong: eosl=%d actionable=%d affected=%d wontfix=%d", eosl, actionable, affected, wontfix)
	}
}

func TestFormatSlackText_Clean(t *testing.T) {
	clean := analyze.Build([]scanner.ImageScan{{Image: "ok:1"}}, genTime)
	out := FormatSlackText(clean)
	if !strings.Contains(out, "All clear") {
		t.Errorf("clean report should say All clear, got:\n%s", out)
	}
}

func TestBuildWebhookPayload(t *testing.T) {
	data, err := json.Marshal(BuildWebhookPayload(sampleReport()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := p["generated_at"]; !ok {
		t.Error("missing generated_at")
	}
	summary, ok := p["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing/wrong type: %T", p["summary"])
	}
	if summary["images_total"].(float64) != 2 {
		t.Errorf("images_total = %v, want 2", summary["images_total"])
	}
	for _, key := range []string{"actionable", "watch", "wont_fix", "eosl_images", "scan_errors"} {
		if _, ok := p[key]; !ok {
			t.Errorf("payload missing %q", key)
		}
	}

	// drill into one actionable finding for field shape
	act := p["actionable"].([]any)
	if len(act) == 0 {
		t.Fatal("actionable empty")
	}
	img := act[0].(map[string]any)
	finds := img["findings"].([]any)
	fnd := finds[0].(map[string]any)
	for _, key := range []string{"package", "installed", "fixed", "severity_counts", "upgrade_risk", "vuln_ids"} {
		if _, ok := fnd[key]; !ok {
			t.Errorf("finding missing %q: %v", key, fnd)
		}
	}
}
