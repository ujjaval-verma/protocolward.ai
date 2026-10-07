// SPDX-License-Identifier: Apache-2.0

package dataplane_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/dataplane"
	"protocolward.ai/ward/internal/obs"
	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/internal/web"
	"protocolward.ai/ward/pkg/detect"
	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// dgaProbe is an md5-family DGA shape (32 lowercase hex + .info); S1's eval
// reports 500/500 recall on this family. requireDetectorFlags fails fast with
// a clear message if S1's calibration ever stops flagging it.
const dgaProbe = "3f9a1c7e5b2d8046af1e9c3b7d5a2e80.info"

const flagsNotBlockedText = "flagged, not blocked — add to blocklist to enforce"

func requireDetectorFlags(t *testing.T, name string) {
	t.Helper()
	a, err := detect.New().Assess(context.Background(), model.Input{Hostname: name})
	if err != nil || a.Verdict != schema.VerdictMalicious {
		t.Fatalf("precondition: detect.New() must flag %q as malicious, got %+v err=%v — replace dgaProbe with a malicious golden row from pkg/detect", name, a, err)
	}
}

// flagsSection returns the HTML between the Flags panel marker and the
// decisions panel marker, so assertions cannot be satisfied by the qname
// appearing in the decisions table instead.
func flagsSection(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `id="flags"`)
	end := strings.Index(body, `id="decisions"`)
	if start < 0 || end < 0 || end < start {
		t.Fatalf("dashboard missing flags/decisions markers (start=%d end=%d):\n%s", start, end, body)
	}
	return body[start:end]
}

// S2 tracer bullet: real detector in the dataplane fork, real web FlagLog,
// real dashboard handler. Proves the DGA-like name is (a) answered from
// upstream — flag-only, never enforced — and (b) listed under Flags.
func TestTracer_BuiltinDetector_FlagsAndStillForwards(t *testing.T) {
	requireDetectorFlags(t, dgaProbe)
	restore := obs.Capture(t)
	defer restore()

	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	store := web.NewStore()
	flags := web.NewFlagLog()
	srv, err := dataplane.NewServer(dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Classifier:      detect.New(),
		Decisions:       store,
		Flags:           flags,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dgaProbe+".", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(msg, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR from upstream (flag-only)", dns.RcodeToString[resp.Rcode])
	}
	if got := r.queries.Load(); got != 1 {
		t.Errorf("flagged name must still be forwarded: upstream queries = %d, want 1", got)
	}

	// Drain the async classify fork before inspecting the FlagLog.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	got := flags.Snapshot()
	if len(got) != 1 {
		t.Fatalf("flags = %+v, want exactly 1", got)
	}
	if got[0].Qname != dgaProbe || got[0].Client != "127.0.0.1" {
		t.Errorf("flag = %+v, want qname %q client 127.0.0.1", got[0], dgaProbe)
	}
	if got[0].Score <= 0 || got[0].Score > 1 || len(got[0].Reasons) == 0 {
		t.Errorf("flag lacks score/reasons: %+v", got[0])
	}

	dash := httptest.NewServer(web.HandlerWithFlags(store, flags))
	defer dash.Close()
	hr, err := http.Get(dash.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer hr.Body.Close()
	raw, _ := io.ReadAll(hr.Body)
	section := flagsSection(t, string(raw))
	for _, want := range []string{dgaProbe, "127.0.0.1", flagsNotBlockedText} {
		if !strings.Contains(section, want) {
			t.Errorf("flags panel missing %q:\n%s", want, section)
		}
	}
}

// fakeAssessor implements both SlowPathClassifier and model.Assessor with a
// fixed result, so flag semantics are tested independently of S1 calibration.
type fakeAssessor struct {
	a             schema.Assessment
	err           error
	assessCalls   atomic.Int64
	classifyCalls atomic.Int64
}

func (f *fakeAssessor) Classify(_ context.Context, _ model.Input) (schema.Verdict, error) {
	f.classifyCalls.Add(1)
	return f.a.Verdict, f.err
}

func (f *fakeAssessor) Assess(_ context.Context, _ model.Input) (schema.Assessment, error) {
	f.assessCalls.Add(1)
	return f.a, f.err
}

type flagCall struct {
	qname, client string
	score         float64
	reasons       []string
}

// recordingFlags is a test dataplane.FlagRecorder.
type recordingFlags struct {
	mu    sync.Mutex
	calls []flagCall
}

func (r *recordingFlags) RecordFlag(qname, client string, score float64, reasonCodes []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, flagCall{qname, client, score, reasonCodes})
}

func (r *recordingFlags) all() []flagCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]flagCall(nil), r.calls...)
}

// runForwardWithFlags starts a Server with classifier + flags (flags may be
// nil) and no policy Engine, sends each qname as an A query, then drains via
// Shutdown so every classify fork has completed before the caller inspects
// state.
func runForwardWithFlags(t *testing.T, classifier dataplane.SlowPathClassifier, flags dataplane.FlagRecorder, qnames ...string) {
	t.Helper()
	runForwardWithFlagsEngine(t, nil, classifier, flags, qnames...)
}

// runForwardWithFlagsEngine is runForwardWithFlags with an explicit policy
// Engine (nil allowed), mirroring cmd/ward serve, which always builds one.
func runForwardWithFlagsEngine(t *testing.T, engine *policy.Engine, classifier dataplane.SlowPathClassifier, flags dataplane.FlagRecorder, qnames ...string) {
	t.Helper()
	r := &fakeResolver{addr: "127.0.0.1:9001", rcode: dns.RcodeSuccess}
	cfg := dataplane.Config{
		ListenAddr:      "127.0.0.1:0",
		Resolvers:       []dataplane.Resolver{r},
		QueryTimeout:    1 * time.Second,
		ShutdownTimeout: 2 * time.Second,
		Classifier:      classifier,
	}
	if engine != nil {
		cfg.Engine = engine
		cfg.BlockResponse = defaultBlockResponse()
	}
	if flags != nil {
		cfg.Flags = flags
	}
	srv, err := dataplane.NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	addr, err := waitForAddr(srv, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range qnames {
		msg := new(dns.Msg)
		msg.SetQuestion(q, dns.TypeA)
		if _, _, err := new(dns.Client).Exchange(msg, addr); err != nil {
			t.Fatalf("exchange %q: %v", q, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func countMsg(records []map[string]any, msg string) int {
	n := 0
	for _, r := range records {
		if r["msg"] == msg {
			n++
		}
	}
	return n
}

func maliciousAssessment() schema.Assessment {
	return schema.Assessment{
		Verdict: schema.VerdictMalicious,
		Score:   0.93,
		Reasons: []schema.Reason{
			{Code: schema.ReasonRareNgrams, Detail: "d", Weight: 0.5},
			{Code: schema.ReasonHighEntropy, Detail: "d", Weight: 0.3},
			{Code: schema.ReasonDigitHeavy, Detail: "d", Weight: 0.1},
			{Code: schema.ReasonLongLabel, Detail: "d", Weight: 0.03},
		},
	}
}

func TestFlags_Malicious_RecordsFlagWithClientScoreTopReasons(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	fa := &fakeAssessor{a: maliciousAssessment()}
	rf := &recordingFlags{}
	runForwardWithFlags(t, fa, rf, "probe.example.com.")

	if fa.assessCalls.Load() != 1 || fa.classifyCalls.Load() != 0 {
		t.Errorf("assess=%d classify=%d, want Assess once and Classify never", fa.assessCalls.Load(), fa.classifyCalls.Load())
	}
	got := rf.all()
	if len(got) != 1 {
		t.Fatalf("flags = %+v, want 1", got)
	}
	want := []string{schema.ReasonRareNgrams, schema.ReasonHighEntropy, schema.ReasonDigitHeavy}
	if got[0].qname != "probe.example.com" || got[0].client != "127.0.0.1" || got[0].score != 0.93 ||
		fmt.Sprint(got[0].reasons) != fmt.Sprint(want) {
		t.Errorf("flag = %+v, want probe.example.com / 127.0.0.1 / 0.93 / %v", got[0], want)
	}
}

func TestFlags_Benign_NoFlag(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	fa := &fakeAssessor{a: schema.Assessment{Verdict: schema.VerdictBenign, Score: 0.05}}
	rf := &recordingFlags{}
	runForwardWithFlags(t, fa, rf, "github.com.")
	if got := rf.all(); len(got) != 0 {
		t.Errorf("benign produced flags: %+v", got)
	}
	rec := findRecordByMsg(obs.Captured(t), "policy: classified")
	if rec == nil || rec["level"] != "DEBUG" {
		t.Errorf("benign classified record = %v, want DEBUG", rec)
	}
	if _, ok := rec["score"]; ok {
		t.Errorf("benign classified record carries flag attrs: %v", rec)
	}
}

// Sibling-adapter shape (Classify only): no flag, and the classified line is
// unchanged (no flag attrs) — DoD bullets 13-15 depend on this path.
func TestFlags_ClassifyOnly_NoFlag_LogUnchanged(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	fc := &fakeClassifier{verdict: schema.VerdictMalicious}
	rf := &recordingFlags{}
	runForwardWithFlags(t, fc, rf, "evilprobe.example.com.")
	if got := rf.all(); len(got) != 0 {
		t.Errorf("Classify-only classifier produced flags: %+v", got)
	}
	rec := findRecordByMsg(obs.Captured(t), "policy: classified")
	if rec == nil {
		t.Fatal("no policy: classified record")
	}
	for _, k := range []string{"score", "reasons", "client", "enforced", "remediation"} {
		if _, ok := rec[k]; ok {
			t.Errorf("sibling-path classified record gained %q: %v", k, rec)
		}
	}
}

// One event, one line: the flag rides on the existing policy: classified
// record. Flags is nil here — proves the nil sink is safe and logging is
// independent of the dashboard.
func TestFlags_LogLine_OnePerFlag(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	runForwardWithFlags(t, &fakeAssessor{a: maliciousAssessment()}, nil, "probe.example.com.")

	recs := obs.Captured(t)
	if n := countMsg(recs, "policy: classified"); n != 1 {
		t.Fatalf("policy: classified lines = %d, want 1; records: %v", n, recs)
	}
	rec := findRecordByMsg(recs, "policy: classified")
	if rec["level"] != "WARN" || rec["verdict"] != "malicious" || rec["qname"] != "probe.example.com" {
		t.Errorf("record = %v", rec)
	}
	if rec["score"] != 0.93 || rec["client"] != "127.0.0.1" || rec["enforced"] != false {
		t.Errorf("flag attrs wrong: %v", rec)
	}
	if fmt.Sprint(rec["reasons"]) != "[rare_ngrams high_entropy digit_heavy]" {
		t.Errorf("reasons = %v", rec["reasons"])
	}
	rem, _ := rec["remediation"].(string)
	if !strings.Contains(rem, "flagged, not blocked") || !strings.Contains(rem, "probe.example.com") {
		t.Errorf("remediation = %q", rem)
	}
	for _, r := range recs {
		if d, ok := r["detail"]; ok {
			t.Errorf("Reason.Detail leaked into logs: %v", d)
		}
	}
}

// S1 contract: invalid hostnames return a wrapped detect.ErrInvalidHostname.
// That is a quiet skip — Debug only, no flag, no Warn — and the
// model-unavailable latch is NOT tripped (the next query is still assessed).
func TestFlags_InvalidHostname_QuietSkip_NoLatch(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	fa := &fakeAssessor{err: fmt.Errorf("detect: label 2: %w", detect.ErrInvalidHostname)}
	rf := &recordingFlags{}
	runForwardWithFlags(t, fa, rf, "a.example.com.", "b.example.com.")

	if got := fa.assessCalls.Load(); got != 2 {
		t.Errorf("assess calls = %d, want 2 (latch must not trip)", got)
	}
	if got := rf.all(); len(got) != 0 {
		t.Errorf("invalid hostname produced flags: %+v", got)
	}
	recs := obs.Captured(t)
	if n := countMsg(recs, "policy: classify skipped"); n != 2 {
		t.Errorf("skipped records = %d, want 2", n)
	}
	for _, r := range recs {
		if r["msg"] == "policy: classify skipped" && r["level"] != "DEBUG" {
			t.Errorf("skip logged at %v, want DEBUG", r["level"])
		}
		if r["level"] == "WARN" || r["level"] == "ERROR" {
			t.Errorf("unexpected %v record: %v", r["level"], r)
		}
	}
	if !errors.Is(fa.err, detect.ErrInvalidHostname) {
		t.Fatal("test setup: fake error must wrap detect.ErrInvalidHostname")
	}
}

// A non-sentinel Assess error on the builtin path (detect.Assess returns
// ctx.Err() on timeout or cancellation) is a Warn with a remediation that
// fits the in-process detector: there is no adapter to investigate. The
// sibling path keeps its adapter-logs remediation. Neither trips the latch.
func TestFlags_NonSentinelError_RemediationMatchesPath(t *testing.T) {
	t.Run("assessor_path_names_builtin_detector", func(t *testing.T) {
		restore := obs.Capture(t)
		defer restore()
		fa := &fakeAssessor{err: context.DeadlineExceeded}
		rf := &recordingFlags{}
		runForwardWithFlags(t, fa, rf, "a.example.com.", "b.example.com.")
		if got := fa.assessCalls.Load(); got != 2 {
			t.Errorf("assess calls = %d, want 2 (no latch)", got)
		}
		if got := rf.all(); len(got) != 0 {
			t.Errorf("error produced flags: %+v", got)
		}
		rec := findRecordByMsg(obs.Captured(t), "policy: classify error")
		if rec == nil || rec["level"] != "WARN" {
			t.Fatalf("want WARN policy: classify error, got %v", rec)
		}
		rem, _ := rec["remediation"].(string)
		if strings.Contains(rem, "adapter") || !strings.Contains(rem, "built-in detector") || !strings.Contains(rem, "answered normally") {
			t.Errorf("remediation = %q, want built-in detector wording with no adapter reference", rem)
		}
	})
	t.Run("sibling_path_keeps_adapter_remediation", func(t *testing.T) {
		restore := obs.Capture(t)
		defer restore()
		fc := &fakeClassifier{err: errors.New("boom")}
		runForwardWithFlags(t, fc, nil, "a.example.com.")
		rec := findRecordByMsg(obs.Captured(t), "policy: classify error")
		if rec == nil {
			t.Fatal("no classify error record on the sibling path")
		}
		if rem, _ := rec["remediation"].(string); !strings.Contains(rem, "investigate adapter logs") {
			t.Errorf("sibling remediation changed: %q", rem)
		}
	})
}

// (b) Allowlist-staleness guard: connectivityProbeZones lists msftncsi.com
// only because the real detector flags it. If a recalibration stops
// flagging it, the entry is dead weight and this fails so it gets reviewed.
func TestFlags_RealDetector_Msftncsi_StillMalicious(t *testing.T) {
	a, err := detect.New().Assess(context.Background(), model.Input{Hostname: "msftncsi.com"})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if a.Verdict != schema.VerdictMalicious {
		t.Errorf("msftncsi.com verdict = %v (score %.3f), want Malicious: connectivityProbeZones entry may be stale", a.Verdict, a.Score)
	}
}

// Real detector, real junk: a root query reaches the fork as "" and an
// underscore label is legitimate. Neither may flag or warn. (_dmarc.github.com,
// not *.example.com: S1 does not score the example TLD at all, so it would
// not exercise underscore acceptance.)
func TestFlags_RealDetector_RootAndUnderscore_Quiet(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	rf := &recordingFlags{}
	runForwardWithFlags(t, detect.New(), rf, ".", "_dmarc.github.com.")
	if got := rf.all(); len(got) != 0 {
		t.Errorf("flags = %+v, want none", got)
	}
	recs := obs.Captured(t)
	for _, r := range recs {
		if r["level"] == "WARN" || r["level"] == "ERROR" {
			t.Errorf("unexpected %v record: %v", r["level"], r)
		}
	}
	// Positive evidence for each query, not just the absence of noise: the
	// root query is a Debug skip, the underscore name is scored (Debug,
	// benign) rather than rejected.
	skip := findRecordByMsg(recs, "policy: classify skipped")
	if skip == nil || skip["level"] != "DEBUG" || skip["reason"] != "not a scorable hostname" {
		t.Errorf("root query: want DEBUG classify skipped (not a scorable hostname), got %v", skip)
	}
	cls := findRecordByMsg(recs, "policy: classified")
	if cls == nil || cls["level"] != "DEBUG" || cls["qname"] != "_dmarc.github.com" {
		t.Errorf("_dmarc.github.com: want DEBUG classified record, got %v", cls)
	}
}

// DD8 / invariant 1 / D7: with a real (non-nil) Engine — cmd/ward serve always
// builds one — the Assessor path must NOT consult DecideWithVerdict, whose
// Malicious → ActionBlock mapping planned enforcement will start applying. The sibling path
// with the same Engine still does (unchanged attribution).
func TestFlags_Assessor_NeverConsultsEngine(t *testing.T) {
	engine := policy.NewEngine(nil, nil)

	t.Run("assessor_path_no_engine", func(t *testing.T) {
		restore := obs.Capture(t)
		defer restore()
		runForwardWithFlagsEngine(t, engine, &fakeAssessor{a: maliciousAssessment()}, &recordingFlags{}, "probe.example.com.")
		rec := findRecordByMsg(obs.Captured(t), "policy: classified")
		if rec == nil {
			t.Fatal("no policy: classified record on the Assessor path")
		}
		if rec["kind"] != "KindNone" || rec["matched"] != "" || rec["enforced"] != false {
			t.Errorf("Assessor path consulted the engine (want kind KindNone, matched empty, enforced false): %v", rec)
		}
	})

	t.Run("sibling_path_unchanged", func(t *testing.T) {
		restore := obs.Capture(t)
		defer restore()
		runForwardWithFlagsEngine(t, engine, &fakeClassifier{verdict: schema.VerdictMalicious}, nil, "evilprobe.example.com.")
		rec := findRecordByMsg(obs.Captured(t), "policy: classified")
		if rec == nil || rec["kind"] != "KindBlock" || rec["matched"] != "(model)" {
			t.Errorf("sibling path attribution changed (want KindBlock/(model), as on main): %v", rec)
		}
	})
}

// DD9: LAN clients' OS connectivity probes are skipped before Assess, so they
// can never be flagged, whatever the detector says. A look-alike outside the
// zone is still assessed.
func TestFlags_ConnectivityProbe_NeverAssessed(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	fa := &fakeAssessor{a: maliciousAssessment()} // flags everything it sees
	rf := &recordingFlags{}
	runForwardWithFlags(t, fa, rf, "msftncsi.com.", "www.msftncsi.com.", "DNS.MSFTNCSI.COM.", "notmsftncsi.com.")

	if got := fa.assessCalls.Load(); got != 1 {
		t.Errorf("assess calls = %d, want 1 (only the look-alike)", got)
	}
	got := rf.all()
	if len(got) != 1 || got[0].qname != "notmsftncsi.com" {
		t.Errorf("flags = %+v, want exactly notmsftncsi.com", got)
	}
	n := 0
	for _, r := range obs.Captured(t) {
		if r["msg"] == "policy: classify skipped" && r["reason"] == "os connectivity probe" {
			n++
			if r["level"] != "DEBUG" {
				t.Errorf("probe skip logged at %v, want DEBUG", r["level"])
			}
		}
	}
	if n != 3 {
		t.Errorf("probe skip records = %d, want 3", n)
	}
}

// DD9 regression guard with the real detector: every connectivity probe
// measured at T0 (2026-10-05) stays unflagged. If S1 is recalibrated and one
// starts scoring ≥ T_mal, this fails: add its zone to connectivityProbeZones
// with the measured score in the comment — do not drop it from this list.
func TestFlags_RealDetector_ConnectivityProbes_NeverFlagged(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	rf := &recordingFlags{}
	runForwardWithFlags(t, detect.New(), rf,
		"msftncsi.com.", "www.msftncsi.com.", "dns.msftncsi.com.", "ipv6.msftncsi.com.",
		"msftconnecttest.com.", "www.msftconnecttest.com.", "ipv6.msftconnecttest.com.",
		"captive.apple.com.", "captive.g.aaplimg.com.",
		"connectivitycheck.gstatic.com.", "connectivitycheck.android.com.", "clients3.google.com.",
		"detectportal.firefox.com.",
		"nmcheck.gnome.org.", "network-test.debian.org.", "connectivity-check.ubuntu.com.",
	)
	if got := rf.all(); len(got) != 0 {
		t.Errorf("connectivity probes flagged: %+v", got)
	}
	for _, r := range obs.Captured(t) {
		if r["level"] == "WARN" || r["level"] == "ERROR" {
			t.Errorf("unexpected %v record: %v", r["level"], r)
		}
	}
}

// panicAssessor simulates a detector bug. In-process classifiers lost the
// sibling's process boundary, so the fork must contain their panics.
type panicAssessor struct{ calls atomic.Int64 }

func (p *panicAssessor) Classify(context.Context, model.Input) (schema.Verdict, error) {
	panic("classify should not be called")
}

func (p *panicAssessor) Assess(context.Context, model.Input) (schema.Assessment, error) {
	p.calls.Add(1)
	panic("detector bug")
}

func TestFlags_ClassifierPanic_Recovered_ServerSurvives(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	pa := &panicAssessor{}
	rf := &recordingFlags{}
	// Two queries: the second proves the server (and the fork) still work
	// after the first panic, and that no latch tripped.
	runForwardWithFlags(t, pa, rf, "a.example.com.", "b.example.com.")

	if got := pa.calls.Load(); got != 2 {
		t.Errorf("assess calls = %d, want 2", got)
	}
	recs := obs.Captured(t)
	if n := countMsg(recs, "policy: classifier panic recovered"); n != 2 {
		t.Fatalf("panic-recovered records = %d, want 2; records: %v", n, recs)
	}
	rec := findRecordByMsg(recs, "policy: classifier panic recovered")
	if rec["level"] != "ERROR" || rec["panic"] != "detector bug" {
		t.Errorf("record = %v", rec)
	}
	if rem, _ := rec["remediation"].(string); rem == "" {
		t.Errorf("missing remediation (invariant 8): %v", rem)
	}
	// (e) A panic is neither a flag nor a model-unavailable latch trip.
	if got := rf.all(); len(got) != 0 {
		t.Errorf("panic produced flags: %+v", got)
	}
	if n := countMsg(recs, "policy: model unavailable"); n != 0 {
		t.Errorf("panic tripped the unavailable latch (%d records)", n)
	}
	// (d) the stack rides as its own bounded attr.
	stack, _ := rec["stack"].(string)
	if stack == "" || len(stack) > 2048+64 {
		t.Errorf("stack attr len = %d, want 1..~2KB", len(stack))
	}
}

// (d) A recovered panic value is bounded to 256 bytes and the stack to ~2KB,
// so a detector bug that formats attacker-influenced bytes cannot flood logs.
type bigPanicAssessor struct{}

func (bigPanicAssessor) Classify(context.Context, model.Input) (schema.Verdict, error) {
	panic("unused")
}

func (bigPanicAssessor) Assess(context.Context, model.Input) (schema.Assessment, error) {
	panic(strings.Repeat("x", 5000))
}

func TestFlags_ClassifierPanic_ValueAndStackBounded(t *testing.T) {
	restore := obs.Capture(t)
	defer restore()
	runForwardWithFlags(t, bigPanicAssessor{}, &recordingFlags{}, "a.example.com.")
	rec := findRecordByMsg(obs.Captured(t), "policy: classifier panic recovered")
	if rec == nil {
		t.Fatal("no panic record")
	}
	pv, _ := rec["panic"].(string)
	if len(pv) == 0 || len(pv) > 256+len("…(truncated)") || !strings.HasPrefix(pv, strings.Repeat("x", 256)) {
		t.Errorf("panic value len = %d, want 256 bytes plus a truncation marker", len(pv))
	}
	stack, _ := rec["stack"].(string)
	if stack == "" || len(stack) > 2048+len("…(truncated)") {
		t.Errorf("stack len = %d, want 1..2KB(+marker)", len(stack))
	}
}
