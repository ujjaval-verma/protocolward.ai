// SPDX-License-Identifier: Apache-2.0

package web_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"protocolward.ai/ward/internal/web"
)

func TestStore_EmptySnapshot_OkFalse(t *testing.T) {
	s := web.NewStore()
	_, ok := s.Snapshot()
	if ok {
		t.Error("empty store: Snapshot ok=true, want false")
	}
}

func TestStore_RecordThenSnapshot(t *testing.T) {
	s := web.NewStore()
	s.Record("example.com", "forward", "")
	d, ok := s.Snapshot()
	if !ok {
		t.Fatal("expected ok=true after Record")
	}
	if d.Qname != "example.com" || d.Action != "forward" {
		t.Errorf("snapshot: got %+v", d)
	}
	if d.At.IsZero() {
		t.Error("At should be set")
	}
}

func TestStore_LastWriteWins(t *testing.T) {
	s := web.NewStore()
	s.Record("first.test", "block", "first")
	s.Record("second.test", "allow", "second")
	d, _ := s.Snapshot()
	if d.Qname != "second.test" || d.Action != "allow" || d.MatchedLabel != "second" {
		t.Errorf("last-write-wins: got %+v", d)
	}
}

func TestStore_ConcurrentRecordsAndSnapshots_NoRace(t *testing.T) {
	s := web.NewStore()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s.Record("concurrent.test", "forward", "")
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = s.Snapshot()
			}
		}()
	}
	wg.Wait()
}

func TestHandler_Healthz_EmptyLastDecision(t *testing.T) {
	s := web.NewStore()
	srv := httptest.NewServer(web.Handler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field: got %v", body["status"])
	}
	if body["last_decision"] != nil {
		t.Errorf("last_decision: got %v, want nil for empty store", body["last_decision"])
	}
	if _, ok := body["uptime_seconds"]; !ok {
		t.Error("uptime_seconds field missing")
	}
}

func TestHandler_Healthz_AfterRecord(t *testing.T) {
	s := web.NewStore()
	s.Record("dashboard-probe.dod.test", "forward", "")

	srv := httptest.NewServer(web.Handler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d want 200", resp.StatusCode)
	}
	var body struct {
		Status       string `json:"status"`
		LastDecision struct {
			Qname  string `json:"qname"`
			Action string `json:"action"`
		} `json:"last_decision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.LastDecision.Qname != "dashboard-probe.dod.test" {
		t.Errorf("qname: got %q want dashboard-probe.dod.test", body.LastDecision.Qname)
	}
	if body.LastDecision.Action != "forward" {
		t.Errorf("action: got %q want forward", body.LastDecision.Action)
	}
}

func TestHandler_Healthz_RejectsNonGet(t *testing.T) {
	s := web.NewStore()
	srv := httptest.NewServer(web.Handler(s))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/healthz", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d want 405", resp.StatusCode)
	}
}

func TestStore_SnapshotAll_NewestFirst(t *testing.T) {
	s := web.NewStore()
	s.Record("a.test", "block", "trackers")
	s.Record("b.test", "forward", "")
	s.Record("c.test", "allow", "manual")

	got := s.SnapshotAll()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].Qname != "c.test" || got[1].Qname != "b.test" || got[2].Qname != "a.test" {
		t.Errorf("order = [%s, %s, %s], want [c, b, a]", got[0].Qname, got[1].Qname, got[2].Qname)
	}
}

func TestStore_SnapshotAll_EmptyReturnsNil(t *testing.T) {
	s := web.NewStore()
	got := s.SnapshotAll()
	if got != nil {
		t.Fatalf("empty store: got %v, want nil", got)
	}
}

func TestStore_SnapshotAll_WrapsAtCap(t *testing.T) {
	s := web.NewStore()
	for i := 0; i < 30; i++ {
		s.Record(fmt.Sprintf("h%02d.test", i), "block", "")
	}
	got := s.SnapshotAll()
	if len(got) != 25 {
		t.Fatalf("len = %d, want 25 (ring cap)", len(got))
	}
	if got[0].Qname != "h29.test" {
		t.Errorf("newest = %s, want h29.test", got[0].Qname)
	}
	if got[24].Qname != "h05.test" {
		t.Errorf("oldest-in-window = %s, want h05.test", got[24].Qname)
	}
}

func TestStore_SnapshotAll_RaceWithRecord(t *testing.T) {
	s := web.NewStore()
	var wg sync.WaitGroup
	const workers = 4
	const perWorker = 200
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				s.Record("x.test", "block", "")
			}
		}()
	}
	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_ = s.SnapshotAll()
			}
		}()
	}
	wg.Wait()
}

func TestHandler_HealthzContentType(t *testing.T) {
	s := web.NewStore()
	srv := httptest.NewServer(web.Handler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandler_IndexRendersDecisions(t *testing.T) {
	s := web.NewStore()
	s.Record("doubleclick.net", "block", "trackers")
	s.Record("github.com", "forward", "")
	s.Record("tripwire.honeytoken.test", "decoy", "tripwire")

	srv := httptest.NewServer(web.Handler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	got := string(body)
	for _, want := range []string{
		"doubleclick.net",
		"github.com",
		"tripwire.honeytoken.test",
		"block",
		"forward",
		"decoy",
		"trackers",
		"action-block",
		"action-forward",
		"action-decoy",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("body missing %q\nbody:\n%s", want, got)
		}
	}
}

func TestHandler_IndexEmptyState(t *testing.T) {
	s := web.NewStore()
	srv := httptest.NewServer(web.Handler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "no decisions yet") {
		t.Errorf("empty body missing empty-state marker:\n%s", body)
	}
}

func TestHandler_IndexUnknownPath404(t *testing.T) {
	s := web.NewStore()
	srv := httptest.NewServer(web.Handler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/does-not-exist")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandler_IndexPostNotAllowed(t *testing.T) {
	s := web.NewStore()
	srv := httptest.NewServer(web.Handler(s))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/", "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func getIndex(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	return string(body)
}

func flagsPanel(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `id="flags"`)
	end := strings.Index(body, `id="decisions"`)
	if start < 0 || end < start {
		t.Fatalf("missing flags/decisions markers:\n%s", body)
	}
	return body[start:end]
}

func TestFlagLog_EmptySnapshot_Nil(t *testing.T) {
	if got := web.NewFlagLog().Snapshot(); got != nil {
		t.Errorf("empty Snapshot = %v, want nil", got)
	}
	var nilLog *web.FlagLog
	if got := nilLog.Snapshot(); got != nil {
		t.Errorf("nil FlagLog Snapshot = %v, want nil", got)
	}
}

// A beaconing implant cycling DGA names must not grow memory without bound.
func TestFlagLog_WrapsAtCap_NewestFirst(t *testing.T) {
	l := web.NewFlagLog()
	for i := 0; i < 60; i++ {
		l.RecordFlag(fmt.Sprintf("d%02d.test", i), "10.0.0.2", 0.9, []string{"rare_ngrams"})
	}
	got := l.Snapshot()
	if len(got) != 50 {
		t.Fatalf("len = %d, want 50 (cap)", len(got))
	}
	if got[0].Qname != "d59.test" || got[49].Qname != "d10.test" {
		t.Errorf("window = %s..%s, want d59.test..d10.test", got[0].Qname, got[49].Qname)
	}
}

func TestFlagLog_CapsReasonCodes_AndCopies(t *testing.T) {
	l := web.NewFlagLog()
	codes := []string{"a", "b", "c", "d", "e"}
	l.RecordFlag("x.test", "10.0.0.2", 0.9, codes)
	codes[0] = "MUTATED"
	got := l.Snapshot()[0].Reasons
	if fmt.Sprint(got) != "[a b c]" {
		t.Errorf("reasons = %v, want [a b c] (capped at 3, defensively copied)", got)
	}
}

func TestFlagLog_ConcurrentRecordAndSnapshot_NoRace(t *testing.T) {
	l := web.NewFlagLog()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.RecordFlag("x.test", "10.0.0.2", 0.9, []string{"rare_ngrams"})
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = l.Snapshot()
			}
		}()
	}
	wg.Wait()
	// The ring is full after 1600 records: the snapshot is exactly the cap
	// and holds no zero-value (unwritten) slots.
	got := l.Snapshot()
	if len(got) > 50 {
		t.Errorf("snapshot len = %d, want <= 50", len(got))
	}
	for i, f := range got {
		if f.Qname == "" || f.At.IsZero() || len(f.Reasons) == 0 {
			t.Errorf("snapshot[%d] is a zero/partial flag: %+v", i, f)
		}
	}
}

// Snapshot must not alias the ring-owned Reasons slices: a caller mutating
// its copy cannot corrupt what the next dashboard render sees.
func TestFlagLog_Snapshot_DeepCopiesReasons(t *testing.T) {
	l := web.NewFlagLog()
	l.RecordFlag("x.test", "10.0.0.2", 0.9, []string{"a", "b"})
	first := l.Snapshot()
	first[0].Reasons[0] = "MUTATED"
	if got := l.Snapshot()[0].Reasons; fmt.Sprint(got) != "[a b]" {
		t.Errorf("reasons after caller mutation = %v, want [a b]", got)
	}
}

func TestFlagLog_RecordFlag_NilReceiver_NoOp(t *testing.T) {
	var l *web.FlagLog
	l.RecordFlag("x.test", "10.0.0.2", 0.9, []string{"a"}) // must not panic
}

func TestHandler_Flags_RendersRow(t *testing.T) {
	l := web.NewFlagLog()
	l.RecordFlag("3f9a1c7e5b2d8046af1e9c3b7d5a2e80.info", "192.168.1.23", 0.876, []string{"rare_ngrams", "digit_heavy"})
	panel := flagsPanel(t, getIndex(t, web.HandlerWithFlags(web.NewStore(), l)))
	for _, want := range []string{
		"3f9a1c7e5b2d8046af1e9c3b7d5a2e80.info",
		"192.168.1.23",
		"0.88",
		"rare_ngrams, digit_heavy",
		"flagged, not blocked — add to blocklist to enforce",
		"<th>hostname</th>", "<th>client</th>", "<th>score</th>", "<th>reasons</th>", "<th>when</th>",
	} {
		if !strings.Contains(panel, want) {
			t.Errorf("flags panel missing %q:\n%s", want, panel)
		}
	}
}

func TestHandler_Flags_EmptyState(t *testing.T) {
	body := getIndex(t, web.Handler(web.NewStore()))
	panel := flagsPanel(t, body)
	if !strings.Contains(panel, "no flags yet") || !strings.Contains(panel, "flagged, not blocked") {
		t.Errorf("empty flags panel:\n%s", panel)
	}
}

// qnames are attacker-influenced. html/template must escape them.
func TestHandler_Flags_EscapesHostileHostname(t *testing.T) {
	hostile := `<script>alert(1)</script>.evil.test`
	l := web.NewFlagLog()
	l.RecordFlag(hostile, "10.0.0.2", 0.9, []string{"rare_ngrams"})
	st := web.NewStore()
	st.Record(hostile, "forward", "")
	body := getIndex(t, web.HandlerWithFlags(st, l))
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("hostile hostname rendered unescaped:\n%s", body)
	}
	if !strings.Contains(flagsPanel(t, body), "&lt;script&gt;alert(1)&lt;/script&gt;.evil.test") {
		t.Errorf("escaped hostname not found in flags panel:\n%s", body)
	}
}
