// Package runner wires the pipeline together: list running images, scan each,
// triage, and notify. It owns the once-per-cycle orchestration and the
// in-process scheduler (docs/ARCHITECTURE.md §2, ADR-003).
package runner

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/config"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
)

// ImageLister enumerates running container images (implemented by docker.Client).
type ImageLister interface {
	RunningImages(ctx context.Context) ([]string, error)
}

// ImageScanner scans one image (implemented by scanner.Trivy).
type ImageScanner interface {
	Scan(ctx context.Context, image string) scanner.ImageScan
}

// Notifier delivers a report (implemented by notify.Notifier).
type Notifier interface {
	Send(ctx context.Context, r analyze.Report) error
}

// Runner holds the collaborators for one scan cycle.
type Runner struct {
	Lister        ImageLister
	Scanner       ImageScanner
	Notifier      Notifier
	NotifyOnClean bool
	Now           func() time.Time
	Log           *slog.Logger
}

func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

// RunOnce executes a single scan cycle. A failure to list images aborts the
// cycle; a failure to scan an individual image is captured in the report (so
// one bad image never sinks the run) and surfaced to the user.
func (r Runner) RunOnce(ctx context.Context) error {
	log := r.log()
	images, err := r.Lister.RunningImages(ctx)
	if err != nil {
		return fmt.Errorf("list running images: %w", err)
	}
	log.Info("scanning images", "count", len(images))

	scans := make([]scanner.ImageScan, 0, len(images))
	for _, img := range images {
		scan := r.Scanner.Scan(ctx, img)
		if scan.Err != nil {
			log.Warn("image scan failed", "image", img, "err", scan.Err)
		}
		scans = append(scans, scan)
	}

	report := analyze.Build(scans, r.now())
	if !report.HasIssues() && !r.NotifyOnClean {
		log.Info("no issues found; skipping notification")
		return nil
	}

	if err := r.Notifier.Send(ctx, report); err != nil {
		return fmt.Errorf("send notification: %w", err)
	}
	log.Info("notification sent",
		"affected", report.AffectedImageCount(),
		"eosl", len(report.EOSLImages),
		"scan_errors", len(report.ScanErrors))
	return nil
}

// Loop runs RunOnce on the schedule until ctx is cancelled. A cycle error is
// logged but does not stop the loop, so a transient failure (e.g. Slack down)
// doesn't kill the agent.
func (r Runner) Loop(ctx context.Context, sched config.ScheduleConfig) error {
	log := r.log()
	if sched.RunOnStart {
		if err := r.RunOnce(ctx); err != nil {
			log.Error("initial scan cycle failed", "err", err)
		}
	}
	for {
		wait := untilNext(sched, r.now())
		log.Info("next scan scheduled", "in", wait.Round(time.Second).String())
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			if err := r.RunOnce(ctx); err != nil {
				log.Error("scan cycle failed", "err", err)
			}
		}
	}
}

// untilNext computes the wait until the next run: to the daily wall-clock time
// if configured, otherwise a fixed 24h interval.
func untilNext(sched config.ScheduleConfig, now time.Time) time.Duration {
	if hour, min, ok := sched.DailyTime(); ok {
		return nextDaily(now, hour, min).Sub(now)
	}
	return 24 * time.Hour
}

// nextDaily returns the next occurrence of hour:min strictly after now.
func nextDaily(now time.Time, hour, min int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, min, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}
