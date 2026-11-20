package resources

import (
	"errors"
	"testing"
	"time"
)

type fakeSensor struct {
	sample Sample
	calls  int
}

func (s *fakeSensor) Sample() Sample { s.calls++; return s.sample }
func TestPressureAdmissionAndRecovery(t *testing.T) {
	healthy := Sample{AvailableKB: 3 * 1024 * 1024, CPU: 5, IO: 0, CPUValid: true, IOValid: true}
	s := &fakeSensor{sample: healthy}
	g := Controller{Sensor: s}
	now := time.Unix(100, 0)
	if g.Capacity(8, now) != 8 {
		t.Fatal("idle ceiling unavailable")
	}
	s.sample.AvailableKB = 400 * 1024
	if g.Capacity(8, now.Add(2*time.Second)) != 0 {
		t.Fatal("low memory admitted jobs")
	}
	s.sample = healthy
	if g.Capacity(8, now.Add(4*time.Second)) != 0 {
		t.Fatal("recovery oscillated")
	}
	if g.Capacity(8, now.Add(12*time.Second)) != 1 {
		t.Fatal("no gradual recovery")
	}
	s.sample.CPU = 80
	if g.Capacity(8, now.Add(14*time.Second)) != 1 {
		t.Fatal("contention admission")
	}
	s.sample = healthy
	for i := 1; i <= 8; i++ {
		g.Capacity(8, now.Add(time.Duration(14+10*i)*time.Second))
	}
	if g.Capacity(8, now.Add(95*time.Second)) != 8 {
		t.Fatal("capacity permanently lost")
	}
}
func TestMalformedTelemetryUsesConservativeCapacity(t *testing.T) {
	d := LinuxSensor{ReadFile: func(p string) ([]byte, error) { return nil, errors.New("unavailable") }}
	s := d.Sample()
	if s.AvailableKB != -1 || s.CPUValid || s.IOValid || (SharedHost{}).Capacity(8, s) != 1 {
		t.Fatal(s)
	}
	for _, v := range []string{"NaN", "Inf", "-1", "101", "bad"} {
		if _, ok := psi([]byte("some avg10="+v), "some"); ok {
			t.Fatal(v)
		}
	}
}

func TestSustainedPressureDoesNotCountAsQuietRecovery(t *testing.T) {
	s := &fakeSensor{sample: Sample{AvailableKB: 400 * 1024, CPUValid: true, IOValid: true}}
	g := Controller{Sensor: s}
	now := time.Unix(100, 0)
	for n := 0; n <= 60; n += 2 {
		if g.Capacity(8, now.Add(time.Duration(n)*time.Second)) != 0 {
			t.Fatal("pressure admission")
		}
	}
	s.sample.AvailableKB = 4 * 1024 * 1024
	if g.Capacity(8, now.Add(62*time.Second)) != 0 {
		t.Fatal("pressure duration counted as quiet time")
	}
	if g.Capacity(8, now.Add(70*time.Second)) != 1 {
		t.Fatal("quiet recovery failed")
	}
}
func TestControllerAmortizesSensorsAndHonorsCeilingChanges(t *testing.T) {
	s := &fakeSensor{sample: Sample{AvailableKB: 4 * 1024 * 1024, CPUValid: true, IOValid: true}}
	g := Controller{Sensor: s}
	now := time.Unix(100, 0)
	for i := 0; i < 100; i++ {
		g.Capacity(8, now)
	}
	if s.calls != 1 {
		t.Fatal("hot sampling", s.calls)
	}
	if g.Capacity(2, now) != 2 {
		t.Fatal("ignored lowered ceiling")
	}
}

func TestNetworkProbeCapacityAndRecovery(t *testing.T) {
	s := &fakeSensor{sample: Sample{AvailableKB: 4096 * 1024, CPU: 29, CPUValid: true, IOValid: true}}
	var policy NetworkProbes
	for _, scenario := range []struct {
		cpu      float64
		capacity int
	}{
		{29, 31}, {40, 23}, {60, 15}, {80, 7}, {92, 2},
	} {
		s.sample.CPU = scenario.cpu
		if got := policy.Capacity(31, s.sample); got != scenario.capacity {
			t.Fatalf("cpu=%.0f: capacity %d, want %d", scenario.cpu, got, scenario.capacity)
		}
	}
	s.sample.AvailableKB = 400 * 1024
	controller := Controller{Sensor: s, Policy: policy, RecoveryInterval: 2 * time.Second}
	now := time.Now()
	if got := controller.Capacity(31, now); got != 0 {
		t.Fatal("critical memory admitted", got)
	}
	s.sample.AvailableKB = 4096 * 1024
	s.sample.CPU = 0
	if got := controller.Capacity(31, now.Add(2*time.Second)); got != 1 {
		t.Fatal("no gradual recovery", got)
	}
	s.sample.IO = 26
	if got := controller.Capacity(31, now.Add(4*time.Second)); got != 0 {
		t.Fatal("critical I/O admitted", got)
	}
}
