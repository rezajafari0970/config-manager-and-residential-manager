package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

// Benchmark the local pipeline with the same 500 inputs supplied by two sources.
// Fetch bodies and probe receipts are fixtures. No proxy or network core runs.
// go test ./internal/panel -run '^$' -bench '^BenchmarkResidential500$' -benchtime=1x
func BenchmarkResidential500(b *testing.B) {
	const count = 500
	raws := make([]string, count)
	residential := make(map[string]bool)
	var positives []string
	for i := range raws {
		raws[i] = fmt.Sprintf("vless://00000000-0000-4000-8000-%012d@192.0.2.10:443?security=tls&sni=example.com#fixture\n", i+1)
		if i%2 == 0 {
			residential[egress.Hash([]byte(raws[i]))] = true
			positives = append(positives, raws[i])
		}
	}
	// Both subscriptions are ordered by the representative raw digest.
	sort.Slice(positives, func(i, j int) bool {
		return egress.Hash([]byte(positives[i])) < egress.Hash([]byte(positives[j]))
	})
	var rawOutput, templateOutput bytes.Buffer
	for _, uri := range positives {
		candidate := egress.Prepare([]byte(uri))
		if len(candidate.Variants) != 2 {
			b.Fatal("invalid fixture plan")
		}
		rawOutput.WriteString(uri)
		rawOutput.WriteByte('\n')
		templateOutput.Write(candidate.Variants[1].Config)
		templateOutput.WriteByte('\n')
	}
	fetch := batchAcquisitionFetch{strings.Join(raws, "")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s, err := Open(filepath.Join(b.TempDir(), "data", "panel.db"), bytes.Repeat([]byte{7}, 32))
		if err != nil {
			b.Fatal(err)
		}
		func() {
			defer s.Close()
			ctx, cancel := context.WithTimeout(b.Context(), 10*time.Minute)
			defer cancel()
			for _, name := range []string{"a", "b"} {
				source := testSource()
				source.URL = "https://" + name + ".example.invalid/fixture"
				if _, err := s.Save(ctx, "", 0, source); err != nil {
					b.Fatal(err)
				}
			}
			b.StartTimer()
			started := time.Now()
			collectBenchmarkSources(b, ctx, s, fetch, count)
			collected := time.Now()
			// The first lane claims production leases. Each concurrent worker
			// submits a complete independent fixture report to the real evaluator.
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					for range count / 4 {
						job, err := s.ClaimEgressLane(ctx, "initial")
						if err != nil || job == nil {
							b.Errorf("claim: job present=%v err=%v", job != nil, err)
							return
						}
						report := syntheticEgress(*job)
						if !residential[job.Hash] {
							// Controls share the synthetic Ads source in the negative cohort.
							for k := range report.Samples {
								if !report.Samples[k].ActualAds {
									report.Samples[k].Source = egress.Hash([]byte("8.8.8.8"))
								}
							}
						}
						if err := s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: report}); err != nil {
							b.Errorf("complete: %v", err)
							return
						}
					}
				})
			}
			wg.Wait()
			if b.Failed() {
				b.FailNow()
			}
			classified := time.Now()
			var receipts, unique, positive, negative int
			if err := s.db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT hash),
				sum(state='RESIDENTIAL' AND definitive=1),sum(state='NO_SPLIT' AND definitive=1)
				FROM egress_events`).Scan(&receipts, &unique, &positive, &negative); err != nil {
				b.Fatal(err)
			}
			if receipts != count || unique != count || positive != count/2 || negative != count/2 {
				b.Fatalf("attempts=%d unique=%d residential=%d no_split=%d", receipts, unique, positive, negative)
			}
			server, err := NewServer(s, "http://127.0.0.1:18191")
			if err != nil {
				b.Fatal(err)
			}
			base := server.origin + "/egress-subscription/" + s.digest("egress-export-v2", "all") + "/"
			handler := server.Handler()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequestWithContext(ctx, "GET", server.origin+"/api/egress?brief=1", nil))
			var panel struct {
				Accounting struct {
					Current     int `json:"current_identities"`
					Missing     int `json:"coverage_missing"`
					First       int `json:"awaiting_first"`
					Assessed    int `json:"assessed_versions"`
					Publication struct{ Published int }
				}
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &panel) != nil || panel.Accounting.Current != count || panel.Accounting.Assessed != count || panel.Accounting.First != 0 || panel.Accounting.Missing != 0 || panel.Accounting.Publication.Published != len(positives) {
				b.Fatalf("panel HTTP %d accounting %+v", w.Code, panel.Accounting)
			}
			for format, expected := range map[string][]byte{"raw.txt": rawOutput.Bytes(), "configs.jsonl": templateOutput.Bytes()} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequestWithContext(ctx, "GET", base+format, nil))
				if w.Code != 200 || w.Header().Get("X-Config-Count") != strconv.Itoa(len(positives)) {
					b.Fatalf("%s: HTTP %d, count %q", format, w.Code, w.Header().Get("X-Config-Count"))
				}
				if !bytes.Equal(w.Body.Bytes(), expected) {
					b.Fatalf("%s: published bytes differ from the expected positive cohort", format)
				}
			}
			b.StopTimer()
			b.Logf("collector=%v classify=%v accounting_and_export=%v", collected.Sub(started), classified.Sub(collected), time.Since(classified))
		}()
	}
	b.ReportMetric(float64(count), "unique/op")
}

func collectBenchmarkSources(b *testing.B, ctx context.Context, s *Store, fetch collect.FetchDriver, count int) {
	b.Helper()
	run, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	engine := collect.NewEngine(s, s.vault, fetch)
	go func() { done <- engine.Run(run) }()
	defer func() {
		stop()
		if err := <-done; err != nil {
			b.Error(err)
		}
	}()
	for {
		var fetched, matched int
		err := s.reader().QueryRowContext(ctx, `SELECT count(*),
			coalesce(sum(state='updated' AND receipt_unique=? AND stored_count=?),0)
			FROM sources WHERE fetch_count>0`, count, count).Scan(&fetched, &matched)
		if err != nil {
			b.Fatal(err)
		}
		if fetched == 2 {
			if matched != 2 {
				b.Fatalf("only %d of two sources committed %d unique inputs", matched, count)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
