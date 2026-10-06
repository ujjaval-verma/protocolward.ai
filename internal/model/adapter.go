// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"

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
}

// ErrNoCommand is returned by New when Config.Command is empty.
var ErrNoCommand = errors.New("model: adapter config: command is empty")

// ErrUnavailable is returned by Classify when the child process is not
// usable — either it exited, it returned a malformed response, an IO
// error occurred, or the context was cancelled mid-call. Once any of
// these fires the adapter is poisoned and every subsequent Classify
// returns ErrUnavailable. SP10c's dataplane fork can therefore handle
// every classifier failure mode with a single
//
//	errors.Is(err, ErrUnavailable)
//
// check + the `policy: model unavailable` log line required by
// invariant 7.
//
// Per pkg/model.Classifier's contract, schema.ErrUnknownVerdict does
// NOT appear at this boundary — a malformed verdict string from the
// child is wrapped as ErrUnavailable with the schema error preserved
// as the wrap cause for diagnostic logging.
var ErrUnavailable = errors.New("model: adapter: child unavailable")

// Adapter implements pkg/model.Classifier by relaying typed Input to a
// sibling child process over newline-delimited JSON on stdio. Concurrent
// Classify calls are serialized by the internal mutex; SP10c's dataplane
// fork is expected to call this from a single dispatch goroutine, but
// the adapter does not assume that.
type Adapter struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	mu       sync.Mutex
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
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("model: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("model: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("model: child start: %w", err)
	}
	return &Adapter{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdout),
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
func (a *Adapter) Classify(ctx context.Context, in model.Input) (schema.Verdict, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.poisoned {
		return 0, ErrUnavailable
	}

	if err := ctx.Err(); err != nil {
		a.poisonLocked()
		return 0, fmt.Errorf("%w: %w", ErrUnavailable, err)
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

	if _, err := a.stdin.Write(payload); err != nil {
		a.poisonLocked()
		return 0, fmt.Errorf("%w: stdin write: %w", ErrUnavailable, err)
	}

	line, err := a.stdout.ReadBytes('\n')
	if err != nil {
		a.poisonLocked()
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

// poisonLocked marks the adapter dead. Must be called with a.mu held.
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
// a.mu to serialize with Classify, so Close blocks until any in-flight
// Classify returns.
func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
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
