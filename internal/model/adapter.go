// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// Config holds the bits Adapter needs to spawn the child runtime. SP10c
// will add a YAML stanza that hydrates this from ward.yaml; SP10b accepts
// it as a Go-value so tests can inject a fake child without touching the
// config loader.
type Config struct {
	// Command is the argv for the child runtime, including binary path.
	// Empty → New returns ErrNoCommand wrapped.
	Command []string
	// Env, when non-nil, is the child's environment. Pass nil to inherit
	// the parent's environment unchanged (os/exec default behavior);
	// otherwise this slice is used verbatim — callers needing the parent
	// env should pass append(os.Environ(), ...).
	Env []string
	// ReplyTimeout bounds one request/reply exchange with the child, from
	// the write to the end of the reply line. Zero means
	// DefaultReplyTimeout. A child that misses it is killed and the adapter
	// is poisoned (ErrUnavailable wrapping ErrNoReply): the newline-JSON
	// stream is out of step after a partial exchange. It is deliberately
	// independent of the Classify ctx, which in the dataplane also covers
	// the wait for the slot; bounding the exchange by that would poison a
	// healthy child after a burst.
	ReplyTimeout time.Duration
}

// DefaultReplyTimeout is the reply timeout when Config.ReplyTimeout is zero:
// the Tier 2 upper bound, equal to the dataplane's default classify timeout.
const DefaultReplyTimeout = 4 * time.Second

// ErrNoCommand is returned by New when Config.Command is empty.
var ErrNoCommand = errors.New("model: adapter config: command is empty")

// ErrUnavailable is returned by Classify when the child process is not
// usable — either it exited, it returned a malformed response, an IO
// error occurred, or it did not reply within Config.ReplyTimeout (wraps
// ErrNoReply). Once any of these fires the adapter is poisoned and
// every subsequent Classify returns ErrUnavailable. A context that ends
// before the request is written is not a child failure: it returns
// ErrSkipped instead and leaves the adapter usable. SP10c's dataplane fork
// therefore handles every child failure mode with a single
//
//	errors.Is(err, ErrUnavailable)
//
// check + the `policy: model unavailable` log line required by
// invariant 7, and counts ErrSkipped as a dropped classification.
//
// Per pkg/model.Classifier's contract, schema.ErrUnknownVerdict does
// NOT appear at this boundary — a malformed verdict string from the
// child is wrapped as ErrUnavailable with the schema error preserved
// as the wrap cause for diagnostic logging.
var ErrUnavailable = errors.New("model: adapter: child unavailable")

// ErrSkipped is returned by Classify when ctx ended before the request was
// written to the child, usually while waiting for an earlier call to
// finish. Nothing was sent, so the wire protocol is still in step and the
// adapter is NOT poisoned; the next call with a live context proceeds.
// The error also wraps ctx.Err().
var ErrSkipped = errors.New("model: adapter: classify skipped, context ended before the call")

// ErrNoReply is wrapped (with ErrUnavailable) when the child took a request
// but did not finish its reply within Config.ReplyTimeout. The stream is out
// of step after that, so the child is killed and the adapter is poisoned.
var ErrNoReply = errors.New("model: adapter: no reply within the reply timeout")

// Adapter implements pkg/model.Classifier by relaying typed Input to a
// sibling child process over newline-delimited JSON on stdio. Concurrent
// Classify calls are serialized: one request is on the wire at a time.
// A caller waiting its turn gives up when its context ends (ErrSkipped).
type Adapter struct {
	cmd          *exec.Cmd
	stdin        *os.File      // deadline-capable; see New
	stdoutF      *os.File      // the raw read end, for SetReadDeadline
	stdout       *bufio.Reader // wraps stdoutF
	replyTimeout time.Duration

	// sem is a one-slot semaphore guarding the fields below and the
	// stdio pipes. A channel, not a sync.Mutex, so Classify can stop
	// waiting when its context ends.
	sem      chan struct{}
	poisoned bool // once set, every Classify returns ErrUnavailable
}

// Compile-time assertion: *Adapter satisfies pkg/model.Classifier. Mirrors
// the SP10a discipline of asserting the contract at the impl site, not
// just at the test site.
var _ model.Classifier = (*Adapter)(nil)

// New spawns the child runtime named in cfg.Command. The returned Adapter
// owns the child's lifetime — Close terminates it. The Adapter is safe
// for concurrent Classify calls.
//
// The context is passed to exec.CommandContext: if ctx is cancelled or
// times out at ANY point while the child is running — not just during
// Start — the child will be SIGKILL'd by os/exec's background goroutine.
// Pass a non-cancellable context (context.Background()) if you want the
// adapter's lifetime controlled solely by Close. Callers MUST call Close
// to reap the child even after a Classify error path.
func New(ctx context.Context, cfg Config) (*Adapter, error) {
	if len(cfg.Command) == 0 {
		return nil, ErrNoCommand
	}
	// gosec G204: cfg.Command is operator-controlled (sourced from
	// ward.yaml in SP10c, hand-rolled in tests here). Spawning an
	// operator-named binary is the entire point of the adapter — the
	// "taint" gosec warns about is the design.
	cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...) //nolint:gosec // see comment above
	if cfg.Env != nil {
		cmd.Env = cfg.Env
	}
	stdinW, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("model: stdin pipe: %w", err)
	}
	stdoutR, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinW.Close()
		return nil, fmt.Errorf("model: stdout pipe: %w", err)
	}
	// The reply timeout is a deadline on the pipes, so they must support
	// one. os/exec returns the *os.File from os.Pipe, pollable on darwin
	// and linux; probe it here so a future toolchain change fails loudly
	// instead of running every exchange unbounded. Nothing is spawned yet.
	stdin, inOK := stdinW.(*os.File)
	stdoutF, outOK := stdoutR.(*os.File)
	if !inOK || !outOK {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		return nil, fmt.Errorf("model: stdio pipes do not support deadlines: %w",
			errors.New("pipe is not an *os.File"))
	}
	if err := errors.Join(stdin.SetWriteDeadline(time.Time{}), stdoutF.SetReadDeadline(time.Time{})); err != nil {
		_ = stdin.Close()
		_ = stdoutF.Close()
		return nil, fmt.Errorf("model: stdio pipes do not support deadlines: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("model: child start: %w", err)
	}
	replyTimeout := cfg.ReplyTimeout
	if replyTimeout <= 0 {
		replyTimeout = DefaultReplyTimeout
	}
	return &Adapter{
		cmd:          cmd,
		stdin:        stdin,
		stdoutF:      stdoutF,
		stdout:       bufio.NewReader(stdoutF),
		replyTimeout: replyTimeout,
		sem:          make(chan struct{}, 1),
	}, nil
}

// request and response are the wire envelopes. They are not exported —
// the contract is the JSON shape, not the Go types. Out-of-tree adapters
// targeting the same wire shape can use different Go types.
type request struct {
	Hostname    string   `json:"hostname"`
	ClientHints []string `json:"client_hints,omitempty"`
	UserAgent   string   `json:"user_agent,omitempty"`
}

type response struct {
	Verdict schema.Verdict `json:"verdict"`
}

// Classify implements pkg/model.Classifier.
//
// ctx bounds the wait for an earlier call and is checked once more before
// the request is written; either way an ended ctx returns ErrSkipped
// without poisoning. Once written, the exchange is bounded by
// Config.ReplyTimeout, not by ctx.
func (a *Adapter) Classify(ctx context.Context, in model.Input) (schema.Verdict, error) {
	select {
	case a.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, fmt.Errorf("%w: %w", ErrSkipped, ctx.Err())
	}
	defer func() { <-a.sem }()

	if a.poisoned {
		return 0, ErrUnavailable
	}

	// select picks at random when both cases are ready, so the slot may
	// have been taken with ctx already done. Nothing is written yet.
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrSkipped, err)
	}

	clean := sanitize(in)
	req := request{
		Hostname:    clean.Hostname,
		ClientHints: clean.ClientHints,
		UserAgent:   clean.UserAgent,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		// Realistically unreachable — request has no channels / funcs.
		a.poisonLocked()
		return 0, fmt.Errorf("%w: marshal: %w", ErrUnavailable, err)
	}
	payload = append(payload, '\n')

	deadline := time.Now().Add(a.replyTimeout)
	if err := a.stdin.SetWriteDeadline(deadline); err != nil {
		a.poisonLocked()
		return 0, fmt.Errorf("%w: stdin deadline: %w", ErrUnavailable, err)
	}
	if err := a.stdoutF.SetReadDeadline(deadline); err != nil {
		a.poisonLocked()
		return 0, fmt.Errorf("%w: stdout deadline: %w", ErrUnavailable, err)
	}

	// A late reply is never read: a poisoned adapter does not touch the
	// pipes again.
	if _, err := a.stdin.Write(payload); err != nil {
		a.poisonLocked()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, fmt.Errorf("%w: %w (%s): stdin write: %w", ErrUnavailable, ErrNoReply, a.replyTimeout, err)
		}
		return 0, fmt.Errorf("%w: stdin write: %w", ErrUnavailable, err)
	}

	line, err := a.stdout.ReadBytes('\n')
	if err != nil {
		a.poisonLocked()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, fmt.Errorf("%w: %w (%s): stdout read: %w", ErrUnavailable, ErrNoReply, a.replyTimeout, err)
		}
		return 0, fmt.Errorf("%w: stdout read: %w", ErrUnavailable, err)
	}

	var resp response
	if err := json.Unmarshal(line, &resp); err != nil {
		a.poisonLocked()
		// Includes schema.ErrUnknownVerdict — wrapped as ErrUnavailable
		// per pkg/model.Classifier's contract.
		return 0, fmt.Errorf("%w: response decode: %w", ErrUnavailable, err)
	}
	return resp.Verdict, nil
}

// poisonLocked marks the adapter dead. Must be called with a.sem held.
// Sends SIGKILL to the child so the OS can reap it via Close's Wait.
func (a *Adapter) poisonLocked() {
	if a.poisoned {
		return
	}
	a.poisoned = true
	// Best-effort: if the child is already dead Kill returns an error
	// we intentionally swallow. Close's Wait is the canonical reap site.
	if a.cmd != nil && a.cmd.Process != nil {
		_ = a.cmd.Process.Kill()
	}
}

// Close terminates the child process and waits for it to exit.
//
// Returns nil for a clean child exit. Returns *exec.ExitError (or another
// non-nil error wrapping the wait) when the child died from a signal
// (e.g. the SIGKILL poisonLocked sends on the IO-error path) or exited
// non-zero. SP10c callers SHOULD log this error at debug level and not
// treat it as fatal — every model-shutdown path produces a non-nil wait
// result that is not actionable.
//
// Idempotent: a second Close call is a no-op and returns nil. Safe to
// call on a poisoned adapter. Safe to call from any goroutine; takes
// a.sem to serialize with Classify, so Close blocks until any in-flight
// Classify returns.
func (a *Adapter) Close() error {
	a.sem <- struct{}{}
	defer func() { <-a.sem }()
	if a.cmd == nil {
		return nil
	}
	// Closing stdin signals the child to exit cleanly on EOF. If the
	// child has already exited Close returns an os.ErrClosed-flavored
	// error we swallow — Wait below is the authoritative reap.
	if a.stdin != nil {
		_ = a.stdin.Close()
	}
	err := a.cmd.Wait()
	a.cmd = nil // make Close idempotent
	return err
}
