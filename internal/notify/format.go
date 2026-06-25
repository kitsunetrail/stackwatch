// Package notify formats an analyze.Report and delivers it to Slack and/or a
// generic webhook. Formatting (pure) is kept separate from delivery (HTTP) so
// the message content is unit-testable without a network.
package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
)

const timeLayout = "2006-01-02 15:04"

// FormatSlackText renders a report as a Slack message body (mrkdwn). A report
// with no issues yields a short "all clear" message.
func FormatSlackText(r analyze.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🛡️ *StackWatch* — scan results for %s\n", r.GeneratedAt.Format(timeLayout))
	fmt.Fprintf(&b, "Running images: %d / affected: %d\n", r.ImagesTotal, r.AffectedImageCount())

	if !r.HasIssues() {
		b.WriteString("\n✅ All clear (no HIGH/CRITICAL vulnerabilities found)\n")
		return b.String()
	}

	if len(r.EOSLImages) > 0 {
		b.WriteString("\n*⛔ Base OS end-of-life (top priority)*\n")
		for _, img := range r.EOSLImages {
			fmt.Fprintf(&b, "• %s — base OS is EOL (no more security updates coming)\n", img)
		}
	}

	writeSection(&b, "✅ Actionable now (fixed)", r.Actionable, true)
	writeSection(&b, "ℹ️ No fix yet (affected / waiting on upstream)", r.Watch, false)
	writeSection(&b, "🔕 Upstream won't fix (will_not_fix)", r.WontFix, false)

	if len(r.ScanErrors) > 0 {
		b.WriteString("\n*⚠️ Scan failures*\n")
		for _, e := range r.ScanErrors {
			fmt.Fprintf(&b, "• %s — %s\n", e.Image, e.Err)
		}
	}

	return b.String()
}

func writeSection(b *strings.Builder, title string, imgs []analyze.ImageFindings, fixed bool) {
	if len(imgs) == 0 {
		return
	}
	fmt.Fprintf(b, "\n*%s*\n", title)
	for _, img := range imgs {
		fmt.Fprintf(b, "%s %s  CRITICAL %d / HIGH %d\n", imageEmoji(img), img.Image, img.CriticalCount(), img.TotalCount()-img.CriticalCount())
		for _, g := range img.Packages {
			b.WriteString("   • ")
			if fixed {
				fmt.Fprintf(b, "%s %s → %s", g.Package, g.InstalledVer, g.FixedVer)
			} else {
				fmt.Fprintf(b, "%s %s (no fix available)", g.Package, g.InstalledVer)
			}
			fmt.Fprintf(b, " (CRITICAL %d / HIGH %d)", g.Critical, g.High)
			if label := riskLabel(g.Risk); label != "" {
				fmt.Fprintf(b, "  %s", label)
			}
			if g.Class == "lang" {
				b.WriteString(" [lang]")
			}
			b.WriteString("\n")
		}
	}
}

func imageEmoji(img analyze.ImageFindings) string {
	if img.CriticalCount() > 0 {
		return "🔴"
	}
	return "🟠"
}

func riskLabel(r analyze.Risk) string {
	switch r {
	case analyze.RiskDistroUpdate:
		return "🟢 Distro security update"
	case analyze.RiskSafe:
		return "🟢 Relatively safe"
	case analyze.RiskCaution:
		return "🟠 Needs care (major version bump)"
	case analyze.RiskUnknown:
		return "⚪ Upgrade risk unknown"
	default:
		return ""
	}
}

// --- generic webhook payload ---

type webhookPayload struct {
	GeneratedAt string         `json:"generated_at"`
	Summary     summary        `json:"summary"`
	EOSLImages  []string       `json:"eosl_images"`
	Actionable  []imagePayload `json:"actionable"`
	Watch       []imagePayload `json:"watch"`
	WontFix     []imagePayload `json:"wont_fix"`
	ScanErrors  []errorPayload `json:"scan_errors"`
}

type summary struct {
	ImagesTotal    int `json:"images_total"`
	ImagesAffected int `json:"images_affected"`
}

type imagePayload struct {
	Image          string           `json:"image"`
	SeverityCounts map[string]int   `json:"severity_counts"`
	Findings       []findingPayload `json:"findings"`
}

type findingPayload struct {
	Package        string         `json:"package"`
	Installed      string         `json:"installed"`
	Fixed          string         `json:"fixed"`
	Status         string         `json:"status"`
	SeverityCounts map[string]int `json:"severity_counts"`
	UpgradeRisk    string         `json:"upgrade_risk"`
	VulnIDs        []string       `json:"vuln_ids"`
}

type errorPayload struct {
	Image string `json:"image"`
	Error string `json:"error"`
}

// BuildWebhookPayload produces the structured JSON payload for the generic
// webhook. It is returned as a value so callers (and tests) can marshal it.
func BuildWebhookPayload(r analyze.Report) any {
	return webhookPayload{
		GeneratedAt: r.GeneratedAt.Format(time.RFC3339),
		Summary: summary{
			ImagesTotal:    r.ImagesTotal,
			ImagesAffected: r.AffectedImageCount(),
		},
		EOSLImages: r.EOSLImages,
		Actionable: imagePayloads(r.Actionable),
		Watch:      imagePayloads(r.Watch),
		WontFix:    imagePayloads(r.WontFix),
		ScanErrors: errorPayloads(r.ScanErrors),
	}
}

func imagePayloads(imgs []analyze.ImageFindings) []imagePayload {
	out := make([]imagePayload, 0, len(imgs))
	for _, img := range imgs {
		findings := make([]findingPayload, 0, len(img.Packages))
		for _, g := range img.Packages {
			findings = append(findings, findingPayload{
				Package:        g.Package,
				Installed:      g.InstalledVer,
				Fixed:          g.FixedVer,
				Status:         string(g.Status),
				SeverityCounts: map[string]int{"CRITICAL": g.Critical, "HIGH": g.High},
				UpgradeRisk:    string(g.Risk),
				VulnIDs:        g.VulnIDs,
			})
		}
		out = append(out, imagePayload{
			Image:          img.Image,
			SeverityCounts: map[string]int{"CRITICAL": img.CriticalCount(), "HIGH": img.TotalCount() - img.CriticalCount()},
			Findings:       findings,
		})
	}
	return out
}

func errorPayloads(errs []analyze.ScanError) []errorPayload {
	out := make([]errorPayload, 0, len(errs))
	for _, e := range errs {
		out = append(out, errorPayload{Image: e.Image, Error: e.Err})
	}
	return out
}
