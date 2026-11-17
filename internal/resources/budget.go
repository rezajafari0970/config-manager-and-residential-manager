package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Budget is a process-shared reservation driver. Only admission uses its short
// flock; no lease, network job, renewal or output transaction holds that lock.
// A permit survives until release or verified owner-process death/replacement.
type Budget struct{ Directory string }
type reservation struct {
	PID     int
	Start   string
	Bytes   int64
	Control bool `json:",omitempty"`
}

var bootOnce sync.Once
var bootID string
var bootError error

func processStart(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	i := strings.LastIndex(string(b), ")")
	if i < 0 {
		return "", errors.New("invalid process stat")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return "", errors.New("short process stat")
	}
	if f[0] == "Z" || f[0] == "X" {
		return "", os.ErrNotExist
	}
	bootOnce.Do(func() {
		var b []byte
		b, bootError = os.ReadFile("/proc/sys/kernel/random/boot_id")
		bootID = strings.TrimSpace(string(b))
	})
	if bootError != nil || bootID == "" {
		return "", errors.New("boot identity unavailable")
	}
	return bootID + ":" + f[19], nil
}
func fields(path string) (map[string]int64, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	out := map[string]int64{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		n, e := strconv.ParseInt(f[1], 10, 64)
		if e != nil {
			return nil, e
		}
		out[strings.TrimSuffix(f[0], ":")] = n
	}
	return out, nil
}
func sharedHeadroom() (available, budget int64, err error) {
	m, e := fields("/proc/meminfo")
	if e != nil {
		return 0, 0, e
	}
	total, available := m["MemTotal"]*1024, m["MemAvailable"]*1024
	if total <= 0 || available < 0 || available > total {
		return 0, 0, errors.New("invalid memory telemetry")
	}
	// Count non-reclaimable manager memory, not file cache which MemAvailable
	// already considers reclaimable. Cores are siblings of their trusted helpers.
	roots := []string{}
	for _, s := range []string{"config-repair", "config-repair-prober", "config-repair-egress"} {
		roots = append(roots, "/sys/fs/cgroup/system.slice/"+s+".service")
	}
	entries, e := os.ReadDir("/sys/fs/cgroup")
	if e != nil {
		return 0, 0, e
	}
	for _, p := range entries {
		n := p.Name()
		if n == "cge-sandboxes" || (strings.HasPrefix(n, "crw") && len(n) == 13) {
			roots = append(roots, "/sys/fs/cgroup/"+n)
		}
	}
	var resident int64
	for _, p := range roots {
		v, e := fields(p + "/memory.stat")
		if os.IsNotExist(e) || os.IsPermission(e) {
			// Root-owned sandbox groups are intentionally private. Omitting their
			// resident memory makes this unprivileged estimate more conservative.
			continue
		}
		if e != nil {
			return 0, 0, e
		}
		resident += v["anon"] + v["shmem"]
	}
	external := max(int64(0), total-available-resident)
	return available, max(int64(0), total-external-512*1024*1024), nil
}

// Try reserves estimated peak working memory before a queue claim. An absent
// Directory explicitly disables this driver for isolated fixtures. Production
// sets one common protected directory for every manager service.
func (b Budget) Try(bytes int64) (func(), bool) {
	if b.Directory == "" {
		return func() {}, true
	}
	available, limit, e := sharedHeadroom()
	if e != nil {
		return nil, false
	}
	return b.try(bytes, available, limit, processStart)
}

// TryCollection lets bounded acquisition continue when heavy queues occupy the
// shared pool. At most128MiB of the512MiB control reserve can be borrowed, while
// the fresh host-memory floor still applies. Normal headroom remains preferred.
func (b Budget) TryCollection(bytes int64) (func(), bool) {
	if release, ok := b.Try(bytes); ok {
		return release, true
	}
	m, e := fields("/proc/meminfo")
	if e != nil {
		return nil, false
	}
	return b.tryClass(bytes, m["MemAvailable"]*1024, 128*1024*1024, processStart, true)
}
func (b Budget) try(bytes, available, limit int64, alive func(int) (string, error)) (func(), bool) {
	return b.tryClass(bytes, available, limit, alive, false)
}
func (b Budget) tryClass(bytes, available, limit int64, alive func(int) (string, error), control bool) (func(), bool) {
	if bytes <= 0 || available < 512*1024*1024+bytes {
		return nil, false
	}
	info, e := os.Lstat(b.Directory)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0007 != 0 {
		return nil, false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, false
	}
	lock, e := os.OpenFile(filepath.Join(b.Directory, "budget.lock"), os.O_CREATE|os.O_RDWR, 0660)
	if e != nil {
		return nil, false
	}
	defer lock.Close()
	// Root helpers and the unprivileged panel share only this owned directory.
	if os.Geteuid() == 0 {
		if lock.Chown(int(owner.Uid), int(owner.Gid)) != nil {
			return nil, false
		}
	}
	if lock.Chmod(0660) != nil {
		return nil, false
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, false
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	entries, e := os.ReadDir(b.Directory)
	if e != nil {
		return nil, false
	}
	var used int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".permit") {
			continue
		}
		path := filepath.Join(b.Directory, entry.Name())
		s, e := os.Lstat(path)
		if e != nil {
			return nil, false
		}
		if !s.Mode().IsRegular() || s.Size() > 1024 {
			return nil, false
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return nil, false
		}
		var r reservation
		if json.Unmarshal(data, &r) != nil || r.PID < 1 || r.Bytes < 1 || r.Start == "" {
			return nil, false
		}
		start, e := alive(r.PID)
		if os.IsNotExist(e) || (e == nil && start != r.Start) {
			if os.Remove(path) != nil {
				return nil, false
			}
			continue
		}
		if e != nil {
			return nil, false
		}
		if control && !r.Control {
			continue
		}
		if r.Bytes > limit-used {
			return nil, false
		}
		used += r.Bytes
	}
	if bytes > limit-used {
		return nil, false
	}
	start, e := alive(os.Getpid())
	if e != nil {
		return nil, false
	}
	data, e := json.Marshal(reservation{PID: os.Getpid(), Start: start, Bytes: bytes, Control: control})
	if e != nil {
		return nil, false
	}
	tmp, e := os.CreateTemp(b.Directory, "pending-")
	if e != nil {
		return nil, false
	}
	name := tmp.Name()
	defer os.Remove(name)
	if os.Geteuid() == 0 {
		e = tmp.Chown(int(owner.Uid), int(owner.Gid))
	}
	if e == nil {
		e = tmp.Chmod(0660)
	}
	if e == nil {
		_, e = tmp.Write(data)
	}
	closeErr := tmp.Close()
	if e != nil || closeErr != nil {
		return nil, false
	}
	path := filepath.Join(b.Directory, fmt.Sprintf("%d-%d-%s.permit", os.Getpid(), time.Now().UnixNano(), filepath.Base(name)))
	if os.Rename(name, path) != nil {
		return nil, false
	}
	return func() { _ = os.Remove(path) }, true
}
