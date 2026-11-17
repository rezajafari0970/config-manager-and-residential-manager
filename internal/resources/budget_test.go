package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const gib = int64(1024 * 1024 * 1024)

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
