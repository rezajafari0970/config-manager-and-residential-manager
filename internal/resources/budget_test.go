package resources

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const gib = int64(1024 * 1024 * 1024)

func TestWaitingLargeProbeAccumulatesReleasedMemory(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	b := Budget{dir}
	alive := func(int) (string, error) { return "boot:100", nil }
	const unit = gib / 8
	var releases []func()
	for range 7 {
		r, ok := b.try(unit, 4*gib, gib, alive)
		if !ok {
			t.Fatal("initial allocation")
		}
		releases = append(releases, r)
	}
	if _, ok := b.tryDemand(3*unit, 4*gib, gib, alive, false, true); ok {
		t.Fatal("overcommitted")
	}
	if _, ok := b.try(unit, 4*gib, gib, alive); ok {
		t.Fatal("small job stole pending capacity")
	}
	releases[0]()
	releases[1]()
	large, ok := b.tryDemand(3*unit, 4*gib, gib, alive, false, true)
	if !ok {
		t.Fatal("large job starved")
	}
	defer large()
	for _, release := range releases {
		release()
	}
	small, ok := b.try(unit, 4*gib, gib, alive)
	if !ok {
		t.Fatal("priority persisted after admission")
	}
	small()
	// A crashed or idle worker cannot reserve capacity forever.
	data, _ := json.Marshal(demand{PID: os.Getpid(), Start: "boot:100", Bytes: gib, Until: time.Now().Add(-time.Second).UnixMilli()})
	os.WriteFile(filepath.Join(dir, "demand-expired.json"), data, 0600)
	small, ok = b.try(unit, 4*gib, gib, alive)
	if !ok {
		t.Fatal("expired demand retained")
	}
	small()
}

func TestSharedReservationsBoundCombinedPipelinesAndRecover(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	b := Budget{dir}
	alive := func(pid int) (string, error) {
		if pid == os.Getpid() {
			return "boot:100", nil
		}
		return "", os.ErrNotExist
	}
	r1, ok := b.try(384*1024*1024, 4*gib, gib, alive)
	if !ok {
		t.Fatal("first reservation")
	}
	r2, ok := b.try(384*1024*1024, 4*gib, gib, alive)
	if !ok {
		t.Fatal("second reservation")
	}
	if _, ok = b.try(384*1024*1024, 4*gib, gib, alive); ok {
		t.Fatal("overcommitted shared headroom")
	}
	r1()
	r3, ok := b.try(384*1024*1024, 4*gib, gib, alive)
	if !ok {
		t.Fatal("release did not recover")
	}
	r2()
	r3()
	data, _ := json.Marshal(reservation{PID: 99999999, Start: "boot:old", Bytes: gib})
	os.WriteFile(filepath.Join(dir, "dead.permit"), data, 0600)
	r, ok := b.try(384*1024*1024, 4*gib, gib, alive)
	if !ok {
		t.Fatal("dead owner not reclaimed")
	}
	r()
	if _, e := os.Stat(filepath.Join(dir, "dead.permit")); !os.IsNotExist(e) {
		t.Fatal("dead permit retained")
	}
}
func TestSharedBudgetReapsPIDReuseAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	b := Budget{dir}
	alive := func(int) (string, error) { return "new-boot:100", nil }
	data, _ := json.Marshal(reservation{PID: os.Getpid(), Start: "old-boot:100", Bytes: gib})
	os.WriteFile(filepath.Join(dir, "reused.permit"), data, 0600)
	r, ok := b.try(128*1024*1024, 4*gib, gib, alive)
	if !ok {
		t.Fatal("reused process identity blocked")
	}
	r()
	if _, ok = b.try(128*1024*1024, 600*1024*1024, gib, alive); ok {
		t.Fatal("control-plane reserve spent")
	}
	os.WriteFile(filepath.Join(dir, "bad.permit"), []byte("truncated"), 0600)
	if _, ok = b.try(128*1024*1024, 4*gib, gib, alive); ok {
		t.Fatal("unknown permit ignored")
	}
}

func TestCollectionReserveSurvivesBusyWorkersWithoutOvercommit(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	b := Budget{dir}
	alive := func(int) (string, error) { return "boot:100", nil }
	heavy, ok := b.try(gib, 4*gib, gib, alive)
	if !ok {
		t.Fatal("heavy admission")
	}
	defer heavy()
	if _, ok = b.try(64*1024*1024, 4*gib, gib, alive); ok {
		t.Fatal("shared budget exceeded")
	}
	a, ok := b.tryClass(64*1024*1024, 4*gib, 128*1024*1024, alive, true)
	if !ok {
		t.Fatal("collector starved")
	}
	defer a()
	c, ok := b.tryClass(64*1024*1024, 4*gib, 128*1024*1024, alive, true)
	if !ok {
		t.Fatal("second collector starved")
	}
	defer c()
	if _, ok = b.tryClass(64*1024*1024, 4*gib, 128*1024*1024, alive, true); ok {
		t.Fatal("control reserve exceeded")
	}
	if _, ok = b.tryClass(64*1024*1024, 550*1024*1024, 128*1024*1024, alive, true); ok {
		t.Fatal("host memory floor bypassed")
	}
	a()
	c()
	r, ok := b.tryClass(64*1024*1024, 4*gib, 128*1024*1024, alive, true)
	if !ok {
		t.Fatal("control permit did not recover")
	}
	r()
}

func TestCompetingPriorityProcessesRetainFIFOAndLendSpareCapacity(t *testing.T) {
	const large = 384 << 20
	const capacity = 3 * large
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	b := Budget{dir}
	alive := func(pid int) (string, error) { return strconv.Itoa(pid) + ":start", nil }
	try := func(pid int, bytes int64, priority bool) (func(), bool) {
		return b.tryDemandForPID(bytes, 4*gib, capacity, alive, false, priority, pid)
	}
	wait := func(pid int) {
		t.Helper()
		if r, ok := try(pid, large, true); ok {
			r()
			t.Fatalf("priority process %d jumped the queue", pid)
		}
	}
	read := func(pid int) demand {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("demand-%d.json", pid)))
		if err != nil {
			t.Fatal(err)
		}
		var d demand
		if err = json.Unmarshal(data, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	// A full pool, two supervisors waiting. Refreshing cannot surrender a turn.
	holds := make([]func(), 3)
	for i := range holds {
		r, ok := try(40, large, false)
		if !ok {
			t.Fatal("setup")
		}
		holds[i] = r
	}
	wait(20)
	before := read(20)
	wait(10)
	wait(20)
	if after := read(20); after.Since != before.Since || after.Until < before.Until {
		t.Fatal("refresh changed or shortened arrival")
	}
	holds[0]()
	wait(10)
	if r, ok := try(50, large/3, false); ok {
		r()
		t.Fatal("small process consumed the oldest waiter's headroom")
	}
	r, ok := try(20, large, true)
	if !ok {
		t.Fatal("oldest large request starved")
	}
	// On its next turn the first process becomes a new arrival behind PID 10.
	wait(20)
	r()
	wait(20)
	r, ok = try(10, large, true)
	if !ok {
		t.Fatal("second process starved")
	}
	r()
	holds[1]()
	// There is enough room for the oldest plus this newcomer; lend the spare.
	r, ok = try(30, large, true)
	if !ok {
		t.Fatal("held capacity beyond the older request")
	}
	second, ok := try(20, large, true)
	if !ok {
		t.Fatal("newcomer consumed reserved headroom")
	}
	second()
	r()
	holds[2]()
}

func TestPriorityDemandTieAndPhysicalFloor(t *testing.T) {
	const large = 384 << 20
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	b := Budget{dir}
	alive := func(int) (string, error) { return "start", nil }
	now := time.Now()
	for _, pid := range []int{21, 13} {
		waiter := demand{PID: pid, Start: "start", Bytes: large, Since: now.UnixNano(), Until: now.Add(demandTTL).UnixMilli()}
		blob, _ := json.Marshal(waiter)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("demand-%d.json", pid)), blob, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Reservation headroom can be ample while host RAM can fit only one.
	const available = 512<<20 + large
	if r, ok := b.tryDemandForPID(large, available, 4*gib, alive, false, true, 21); ok {
		r()
		t.Fatal("equal timestamp ignored PID tie-breaker")
	}
	if r, ok := b.tryDemandForPID(large, available-1, 4*gib, alive, false, true, 13); ok {
		r()
		t.Fatal("priority spent control floor")
	}
	r, ok := b.tryDemandForPID(large, available, 4*gib, alive, false, true, 13)
	if !ok {
		t.Fatal("winning wait never admitted")
	}
	r()
}
