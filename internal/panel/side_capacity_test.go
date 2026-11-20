//go:build sidecapacity

package panel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/side"
)

func measureCapacityJob(ctx context.Context, s *Store, j *SideJob, port int, warpOff bool, helper, dir string) error {
	plan := side.Prepare(j.Raw)
	if plan.RawCandidate == nil || len(plan.Candidates) == 0 {
		return fmt.Errorf("unprepared fixture")
	}
	input, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	run := exec.CommandContext(ctx, "python3", helper, "run", strconv.Itoa(port), dir)
	run.Stdin = bytes.NewReader(input)
	output, err := run.CombinedOutput()
	if err != nil {
		return fmt.Errorf("measure: %w %q", err, output)
	}
	var r SideResult
	if err = json.Unmarshal(output, &r); err != nil {
		return fmt.Errorf("measure: %w %q", err, output)
	}
	r.Identity, r.Hash, r.Token = j.Identity, j.Hash, j.Token
	for _, key := range sideServices {
		want := "passed"
		if key == "warp" && warpOff {
			want = "warp_not_active"
		}
		if r.Evidence[key] != want {
			return fmt.Errorf("wrong fixture evidence for %s: got %v", key, r.Evidence)
		}
	}
	if r.Code == "passed" {
		r.Candidate = plan.Candidates[0].Config
	}
	if err = s.CompleteSide(ctx, r); err != nil {
		return fmt.Errorf("commit %s: %w; evidence %v", r.Code, err, r.Evidence)
	}
	return nil
}

// Run with go test -tags sidecapacity -run '^TestSideCapacity$' -count=1 -timeout 30m -v ./internal/panel.
// This measures source admission, vault, leases, real curl through a closed TLS/SOCKS
// service fixture and verified SQLite receipts. It does not launch a VPN core or make
// internet requests. The fixture exposes different WARP states on two loopback ports.
func TestSideCapacity(t *testing.T) {
	n, slots := 2000, 16
	for key, value := range map[string]*int{"SIDE_TEST_COUNT": &n, "SIDE_TEST_SLOTS": &slots} {
		if raw, ok := os.LookupEnv(key); ok {
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 || v > 2000 || key == "SIDE_TEST_SLOTS" && v > side.MaxWorkers {
				t.Fatalf("invalid %s", key)
			}
			*value = v
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	helper := filepath.Join("testdata", "side_capacity.py")
	cmd := exec.CommandContext(ctx, "python3", helper, "serve", dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	var ports [2]int
	line, err := bufio.NewReader(stdout).ReadBytes('\n')
	if err != nil || json.Unmarshal(line, &ports) != nil || ports[0] == 0 || ports[1] == 0 {
		t.Fatalf("fixture startup: %q %v", line, err)
	}

	s := testStore(t)
	src, err := s.Save(ctx, "", 0, testSource())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	fixture := cardinalityFixture(t, s, n)
	if err := s.Complete(ctx, claimOne(t, s, src), fixture, time.Now()); err != nil {
		t.Fatal(err)
	}
	portsByID := make(map[string]int, n)
	for i, item := range fixture.Items {
		port := 1
		if i%10 == 0 {
			port = 0
		}
		portsByID[item.Identity] = ports[port]
	}
	measuring := time.Now()
	var total atomic.Int64
	var receiptError error
	var once sync.Once
	var workers sync.WaitGroup
	for range slots {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ctx.Err() == nil && total.Load() < int64(n) {
				j, err := s.ClaimSide(ctx)
				if err == nil && j == nil {
					time.Sleep(25 * time.Millisecond)
					continue
				}
				if err == nil {
					port := portsByID[j.Identity]
					err = measureCapacityJob(ctx, s, j, port, port == ports[1], helper, dir)
				}
				if err != nil {
					once.Do(func() { receiptError = err; cancel() })
					return
				}
				if done := total.Add(1); done%250 == 0 {
					t.Logf("%d/%d time from acquisition %s", done, n, time.Since(start).Round(time.Second))
				}
			}
		}()
	}
	workers.Wait()
	if receiptError != nil {
		t.Fatal(receiptError)
	}
	duration := time.Since(start)
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	s.Close()
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Complete(ctx, claimOne(t, s, src), fixture, time.Now()); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, n, "SELECT count(*) FROM side_jobs WHERE attempts=1 AND finished>0")
	stats, err := s.SideCounts(ctx)
	passed := (n + 9) / 10
	if err != nil || stats.Accepted != passed || stats.Rejected != n-passed || stats.Pending+stats.Running+stats.Inconclusive != 0 {
		t.Fatalf("reopen and reacquire: %+v %v", stats, err)
	}
	t.Logf("configs=%d; complete ten-check profiles=%d; accepted=%d rejected=%d; slots=%d; acquisition=%s; acquisition to durable finish=%s; configs/min=%.1f",
		n, n, stats.Accepted, stats.Rejected, slots, measuring.Sub(start).Round(time.Millisecond), duration.Round(time.Millisecond), float64(n)/duration.Minutes())
	if n == 2000 && duration > 15*time.Minute {
		t.Errorf("2000 identity cohort exceeded 15 minutes (%s)", duration)
	}
	wantServices, err := json.Marshal(sideServices)
	if err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, n, `SELECT count(*) FROM side_jobs j WHERE
		NOT EXISTS(SELECT 1 FROM json_each(?) AS k WHERE
		coalesce(json_extract(j.evidence,'$.'||k.value), '') !=
		CASE WHEN k.value='warp' AND j.state='rejected' THEN 'warp_not_active' ELSE 'passed' END)`, string(wantServices))

}
