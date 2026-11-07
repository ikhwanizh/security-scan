package scanner

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sync/errgroup"

	"kscan/internal/finding"
)

type Status string

const (
	StatusOK      Status = "ok"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
)

// Result is the outcome of one scanner. A failing scanner never aborts the others.
type Result struct {
	Scanner  string            `json:"scanner"`
	Status   Status            `json:"status"`
	Reason   string            `json:"reason,omitempty"`
	Duration time.Duration     `json:"duration"`
	Findings []finding.Finding `json:"-"`
}

// RunAll runs the applicable scanners in parallel, each with its own timeout.
// Results come back in the same order as scanners.
func RunAll(ctx context.Context, repo string, scanners []Scanner, opts Options, timeout time.Duration) []Result {
	results := make([]Result, len(scanners))
	var g errgroup.Group
	for i, s := range scanners {
		results[i].Scanner = s.Name()
		if !s.Applies(opts.Stack) {
			results[i].Status = StatusSkipped
			results[i].Reason = "not applicable to detected stack"
			continue
		}
		if _, err := s.Available(); err != nil {
			results[i].Status = StatusSkipped
			if opts.Required[s.Name()] {
				results[i].Status = StatusError
			}
			results[i].Reason = err.Error()
			continue
		}
		g.Go(func() error {
			sctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := time.Now()
			fs, err := s.Run(sctx, repo, opts)
			results[i].Duration = time.Since(start).Round(time.Millisecond)
			if errors.Is(err, ErrNoTargets) {
				results[i].Status = StatusSkipped
				results[i].Reason = err.Error()
				return nil
			}
			if err != nil {
				results[i].Status = StatusError
				results[i].Reason = err.Error()
				return nil
			}
			results[i].Status = StatusOK
			results[i].Findings = fs
			return nil
		})
	}
	_ = g.Wait()
	return results
}
