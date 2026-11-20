// Package resources controls admission, never evidence or running jobs.
// Sensors and policies are independent drivers so telemetry failure and pressure
// recovery can be tested without changing the host or the queue implementation.
package resources

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Sample struct {
	AvailableKB       int64
	CPU, IO           float64
	CPUValid, IOValid bool
}
type Sensor interface{ Sample() Sample }
type Policy interface{ Capacity(int, Sample) int }
type LinuxSensor struct{ ReadFile func(string) ([]byte, error) }

func psi(b []byte, kind string) (float64, bool) {
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != kind {
			continue
		}
		for _, v := range f[1:] {
			if strings.HasPrefix(v, "avg10=") {
				n, e := strconv.ParseFloat(strings.TrimPrefix(v, "avg10="), 64)
				return n, e == nil && n >= 0 && n <= 100
			}
		}
	}
	return 0, false
}
func (d LinuxSensor) Sample() Sample {
	read := d.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	s := Sample{AvailableKB: -1}
	if b, e := read("/proc/meminfo"); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) == 3 && f[0] == "MemAvailable:" && f[2] == "kB" {
				if n, e := strconv.ParseInt(f[1], 10, 64); e == nil && n >= 0 {
					s.AvailableKB = n
				}
			}
		}
	}
	if b, e := read("/proc/pressure/cpu"); e == nil {
		s.CPU, s.CPUValid = psi(b, "some")
	}
	if b, e := read("/proc/pressure/io"); e == nil {
		s.IO, s.IOValid = psi(b, "full")
	}
	return s
}

// SharedHost preserves headroom when tasks wait for CPU or memory. An idle host
// admits the complete configured ceiling; no fixed CPU quota is introduced.
type SharedHost struct{}

func (SharedHost) Capacity(maximum int, s Sample) int {
	if maximum < 1 {
		return 0
	}
	if s.AvailableKB >= 0 && s.AvailableKB < 512*1024 || s.IOValid && s.IO >= 25 {
		return 0
	}
	n := maximum
	if s.AvailableKB < 0 || !s.CPUValid || !s.IOValid {
		n = min(n, 1)
	}
	if s.AvailableKB >= 0 && s.AvailableKB < 1024*1024 {
		n = min(n, 1)
	} else if s.AvailableKB < 1536*1024 {
		n = min(n, 2)
	}
	if s.CPUValid && s.CPU >= 70 || s.IOValid && s.IO >= 15 {
		n = min(n, 1)
	} else if s.CPUValid && s.CPU >= 40 || s.IOValid && s.IO >= 8 {
		n = min(n, max(1, maximum/2))
	}
	return n
}

// NetworkProbes keep concurrent TLS sessions alive while they wait for remote
// endpoints. CPU "some" pressure includes every short-lived runnable process,
// so apply gradual limits here while retaining the shared memory and I/O rules.
type NetworkProbes struct{}

func (NetworkProbes) Capacity(maximum int, s Sample) int {
	cpu := s.CPU
	s.CPU = 0
	n := (SharedHost{}).Capacity(maximum, s)
	switch {
	case cpu >= 90:
		return min(n, 2)
	case cpu >= 75:
		return min(n, max(2, maximum/4))
	case cpu >= 55:
		return min(n, max(2, maximum/2))
	case cpu >= 35:
		return min(n, max(2, maximum*3/4))
	}
	return n
}

type Controller struct {
	mu               sync.Mutex
	Sensor           Sensor
	Policy           Policy
	RecoveryInterval time.Duration // defaults to ten seconds
	current, maximum int
	sampled, changed time.Time
}

// Capacity samples at most once per two seconds, decreases admission promptly,
// then restores one slot per quiet ten seconds. Existing jobs are never killed.
func (g *Controller) Capacity(maximum int, now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.sampled.IsZero() && maximum == g.maximum && now.Sub(g.sampled) < 2*time.Second {
		return g.current
	}
	sensor := g.Sensor
	if sensor == nil {
		sensor = LinuxSensor{}
	}
	policy := g.Policy
	if policy == nil {
		policy = SharedHost{}
	}
	recovery := g.RecoveryInterval
	if recovery <= 0 {
		recovery = 10 * time.Second
	}
	target := max(0, min(maximum, policy.Capacity(maximum, sensor.Sample())))
	if g.sampled.IsZero() || target < g.current {
		g.current = target
		g.changed = now
	} else if target == g.current && target < maximum {
		// Sustained pressure is not quiet recovery time.
		g.changed = now
	} else if target > g.current && now.Sub(g.changed) >= recovery {
		g.current = min(target, g.current+1)
		g.changed = now
	}
	g.maximum = maximum
	g.sampled = now
	return g.current
}
