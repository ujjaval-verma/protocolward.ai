// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/upstream"
)

// BenchmarkQuery_Burst100_20ms fires 100 concurrent queries per op at a 20 ms
// upstream on one client reused across ops. Errors are counted, never fatal,
// so a client that cannot keep up still reports its numbers.
func BenchmarkQuery_Burst100_20ms(b *testing.B) {
	srv := newFakeDoT(b, FakeDoTOptions{Rcode: dns.RcodeSuccess, Latency: 20 * time.Millisecond})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		b.Fatalf("new: %v", err)
	}
	defer client.Close()

	const n = 100
	var errs atomic.Int64
	var totalQPS, totalSlowestMs float64
	b.ResetTimer()
	for op := 0; op < b.N; op++ {
		start := make(chan struct{})
		var slowest atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				q0 := time.Now()
				if _, err := client.Query(ctx, newMsg()); err != nil {
					errs.Add(1)
				}
				d := int64(time.Since(q0))
				for {
					cur := slowest.Load()
					if d <= cur || slowest.CompareAndSwap(cur, d) {
						break
					}
				}
			}()
		}
		t0 := time.Now()
		close(start)
		wg.Wait()
		el := time.Since(t0)
		totalQPS += float64(n) / el.Seconds()
		totalSlowestMs += float64(slowest.Load()) / float64(time.Millisecond)
	}
	b.StopTimer()
	b.ReportMetric(totalQPS/float64(b.N), "qps")
	b.ReportMetric(totalSlowestMs/float64(b.N), "slowest-ms")
	b.ReportMetric(float64(errs.Load()), "errors")
}

// BenchmarkQuery_Serial_NoLatency runs 200 sequential queries per op against
// a zero-latency upstream: the per-query overhead of the client.
func BenchmarkQuery_Serial_NoLatency(b *testing.B) {
	srv := newFakeDoT(b, FakeDoTOptions{Rcode: dns.RcodeSuccess})
	client, err := upstream.New(fakeConfig(srv))
	if err != nil {
		b.Fatalf("new: %v", err)
	}
	defer client.Close()

	const n = 200
	var errs int64
	var total time.Duration
	b.ResetTimer()
	for op := 0; op < b.N; op++ {
		t0 := time.Now()
		for i := 0; i < n; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if _, err := client.Query(ctx, newMsg()); err != nil {
				errs++
			}
			cancel()
		}
		total += time.Since(t0)
	}
	b.StopTimer()
	b.ReportMetric(float64(total.Microseconds())/float64(b.N*n), "us/query")
	b.ReportMetric(float64(errs), "errors")
}
