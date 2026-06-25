package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/config"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
)

type fakeLister struct {
	images []string
	err    error
}

func (f fakeLister) RunningImages(context.Context) ([]string, error) { return f.images, f.err }

type fakeScanner struct {
	byImage map[string]scanner.ImageScan
}

func (f fakeScanner) Scan(_ context.Context, image string) scanner.ImageScan {
	if s, ok := f.byImage[image]; ok {
		return s
	}
	return scanner.ImageScan{Image: image}
}

type fakeNotifier struct {
	called bool
	report analyze.Report
}

func (f *fakeNotifier) Send(_ context.Context, r analyze.Report) error {
	f.called = true
	f.report = r
	return nil
}

var clock = func() time.Time { return time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC) }

func TestRunOnce_NotifiesWhenIssuesFound(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister: fakeLister{images: []string{"vuln:1"}},
		Scanner: fakeScanner{byImage: map[string]scanner.ImageScan{
			"vuln:1": {Image: "vuln:1", Findings: []scanner.Finding{
				{Image: "vuln:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
			}},
		}},
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.called {
		t.Fatal("notifier not called despite findings")
	}
	if notif.report.ImagesTotal != 1 {
		t.Errorf("ImagesTotal = %d, want 1", notif.report.ImagesTotal)
	}
}

func TestRunOnce_SkipsNotificationWhenCleanByDefault(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister:   fakeLister{images: []string{"clean:1"}},
		Scanner:  fakeScanner{},
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if notif.called {
		t.Error("notifier called for clean report with NotifyOnClean=false")
	}
}

func TestRunOnce_NotifiesWhenCleanIfConfigured(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister:        fakeLister{images: []string{"clean:1"}},
		Scanner:       fakeScanner{},
		Notifier:      notif,
		NotifyOnClean: true,
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.called {
		t.Error("notifier not called for clean report with NotifyOnClean=true")
	}
}

func TestRunOnce_ListErrorAborts(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister:   fakeLister{err: errors.New("docker down")},
		Scanner:  fakeScanner{},
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when listing fails")
	}
	if notif.called {
		t.Error("notifier should not be called when listing fails")
	}
}

func TestRunOnce_ScanErrorStillNotifies(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister: fakeLister{images: []string{"broken:1"}},
		Scanner: fakeScanner{byImage: map[string]scanner.ImageScan{
			"broken:1": {Image: "broken:1", Err: errors.New("pull failed")},
		}},
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.called {
		t.Fatal("scan failures should still trigger a notification")
	}
	if len(notif.report.ScanErrors) != 1 {
		t.Errorf("ScanErrors = %d, want 1", len(notif.report.ScanErrors))
	}
}

func TestNextDaily(t *testing.T) {
	now := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	// 09:00 already passed today → tomorrow 09:00
	got := nextDaily(now, 9, 0)
	want := time.Date(2026, 6, 25, 9, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("nextDaily past = %v, want %v", got, want)
	}
	// 18:00 still ahead today → today 18:00
	got = nextDaily(now, 18, 0)
	want = time.Date(2026, 6, 24, 18, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("nextDaily future = %v, want %v", got, want)
	}
}

func TestUntilNext_IntervalMode(t *testing.T) {
	// empty daily_at → 24h interval
	d := untilNext(config.ScheduleConfig{}, clock())
	if d != 24*time.Hour {
		t.Errorf("interval mode = %v, want 24h", d)
	}
}
