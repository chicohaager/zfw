// Package dockerwatch keeps the compiled ruleset in sync with the live
// Docker container inventory. A rule bound to a container (v0.5.7) uses
// that container's currently-published ports; when the container starts,
// stops or restarts with different ports, the compiled script would
// otherwise stay stale until the next rules POST or daemon restart.
//
// The watcher streams `docker events` and triggers a debounced recompile
// on each container lifecycle event. It deliberately does NOT apply the
// firewall — changing the live ruleset without an explicit operator
// action (Safe-Apply) is out of scope; the watcher only keeps the
// generated compiled.sh and the dashboard's view current. v1.0.13.
package dockerwatch

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os/exec"
	"time"
)

// defaultDebounce coalesces a burst of events (e.g. `docker compose up`
// starting ten containers) into a single recompile.
const defaultDebounce = 3 * time.Second

// Watcher triggers a debounced recompile on Docker container lifecycle
// events. A nil logger discards messages.
type Watcher struct {
	recompile func(context.Context) error
	log       *slog.Logger
	debounce  time.Duration
}

// New returns a Watcher that calls recompile (typically Server.Recompile)
// on debounced container events.
func New(recompile func(context.Context) error, log *slog.Logger) *Watcher {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Watcher{recompile: recompile, log: log, debounce: defaultDebounce}
}

// Run blocks until ctx is cancelled. It (re)starts `docker events` with a
// fixed backoff between restarts and feeds the event stream to consume.
// On a host without docker it logs once and returns — the watcher is a
// best-effort convenience, never a hard dependency.
func (w *Watcher) Run(ctx context.Context) {
	if _, err := exec.LookPath("docker"); err != nil {
		w.log.Info("dockerwatch disabled — docker not found", "err", err)
		return
	}
	const backoff = 5 * time.Second
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "docker", "events",
			"--filter", "type=container",
			"--filter", "event=start",
			"--filter", "event=die",
			"--format", "{{.Status}} {{.Actor.Attributes.name}}")
		stdout, err := cmd.StdoutPipe()
		if err == nil && cmd.Start() == nil {
			w.consume(ctx, stdout)
			_ = cmd.Wait()
		}
		// The events stream ended (docker restart, daemon down) — wait
		// out the backoff before reconnecting, unless we're shutting down.
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// consume reads container events from r and triggers a debounced
// recompile. It returns when r is exhausted or ctx is cancelled.
// Exposed (unexported but directly testable) so the debounce/trigger
// logic can be exercised without a real docker daemon.
func (w *Watcher) consume(ctx context.Context, r io.Reader) {
	// events is a coalescing signal: a full buffer means "recompile
	// already pending", so a burst of lines collapses to one tick.
	events := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			select {
			case events <- struct{}{}:
			default: // a recompile is already queued — coalesce
			}
		}
	}()

	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-done:
			// Stream ended; honour a pending debounce before returning so
			// the last burst is not dropped.
			if timerC != nil {
				w.fire(ctx)
			}
			return
		case <-events:
			if timer == nil {
				timer = time.NewTimer(w.debounce)
			} else {
				timer.Reset(w.debounce)
			}
			timerC = timer.C
		case <-timerC:
			timerC = nil
			w.fire(ctx)
		}
	}
}

// fire runs one recompile with its own timeout, logging the outcome.
func (w *Watcher) fire(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if err := w.recompile(ctx); err != nil {
		w.log.Warn("dockerwatch recompile failed", "err", err)
		return
	}
	w.log.Info("dockerwatch recompiled rules after container event")
}
