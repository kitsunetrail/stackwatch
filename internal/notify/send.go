package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
)

// Notifier delivers a report to a destination.
type Notifier interface {
	Send(ctx context.Context, r analyze.Report) error
}

// defaultClient is used when a notifier has no client configured.
var defaultClient = &http.Client{Timeout: 15 * time.Second}

// SlackNotifier posts a formatted text message to a Slack Incoming Webhook.
type SlackNotifier struct {
	WebhookURL string
	Client     *http.Client
}

func (n SlackNotifier) Send(ctx context.Context, r analyze.Report) error {
	body := map[string]string{"text": FormatSlackText(r)}
	return postJSON(ctx, client(n.Client), n.WebhookURL, body)
}

// WebhookNotifier posts the structured JSON payload to a generic endpoint.
type WebhookNotifier struct {
	URL    string
	Client *http.Client
}

func (n WebhookNotifier) Send(ctx context.Context, r analyze.Report) error {
	return postJSON(ctx, client(n.Client), n.URL, BuildWebhookPayload(r))
}

// MultiNotifier fans a report out to several notifiers, attempting all even if
// some fail, and joining their errors.
type MultiNotifier []Notifier

// Multi builds a MultiNotifier from the given notifiers.
func Multi(notifiers ...Notifier) MultiNotifier { return MultiNotifier(notifiers) }

func (m MultiNotifier) Send(ctx context.Context, r analyze.Report) error {
	var errs []error
	for _, n := range m {
		if err := n.Send(ctx, r); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return defaultClient
}

func postJSON(ctx context.Context, c *http.Client, url string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("post to %s: %w", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("post to %s: unexpected status %s", url, resp.Status)
	}
	return nil
}
