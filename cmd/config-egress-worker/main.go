// Bounded adaptive supervisor for finite Ads egress investigations.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/resources"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/worker"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type client struct{ http *http.Client }

type apiStatus int

func (s apiStatus) Error() string { return fmt.Sprintf("api_status_%d", int(s)) }

func (c client) call(ctx context.Context, path string, in, out any) error {
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "http://unix/egress/"+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	r, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return apiStatus(r.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(out)
	}
	return nil
}

// A lost response can follow a committed transaction. Replaying the same
// token and revision lets the panel fence duplicates. A conflict can also
// mean the lease expired, so it never counts as an acknowledged completion.
func (c client) sendLeased(ctx context.Context, path string, body any) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for attempt := 0; ; attempt++ {
		err := c.call(ctx, path, body, nil)
		if err == nil || attempt == 2 {
			return err
		}
		var status apiStatus
		var transport net.Error
		if errors.As(err, &status) {
			switch status {
			case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
				http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			default:
				return err
			}
		} else if !errors.As(err, &transport) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 250 * time.Millisecond):
		}
	}
}

type bounded struct {
	bytes.Buffer
	max int
}

func (b *bounded) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("driver output limit")
	}
	return b.Buffer.Write(p)
}
func clean(helper, prefix string, slot int, run string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := []string{helper, "--prefix", prefix, "--slot", fmt.Sprint(slot), "--cleanup"}
	if run != "" {
		args = append(args, "--run-id", run)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", args...)
	cmd.WaitDelay = 2 * time.Second
	_ = cmd.Run()
}
func execute(ctx context.Context, c client, driver *driverSession, j egress.Job) {
	started := egress.Now()
	var p egress.Plan
	r := egress.Report{Version: egress.Version, Hash: j.Hash, Started: started, Finished: started, Code: "driver_unavailable"}
	switch {
	case j.Issue != "":
		r.Code = j.Issue
	case egress.Hash(j.Raw) != j.Hash:
		r.Code = "input_unavailable"
	default:
		p = egress.Prepare(j.Raw)
		if p.Code == egress.AmbiguousVMessTransport {
			r.Code = p.Code
		}
	}
	if len(p.Variants) == 2 {
		job, cancel := context.WithTimeout(ctx, 220*time.Second)
		defer cancel()
		done := make(chan struct{})
		leaseLost := make(chan struct{})
		defer close(done)
		go func() {
			ticker := time.NewTicker(20 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-job.Done():
					return
				case <-ticker.C:
					if c.sendLeased(job, "renew", egress.Job{Hash: j.Hash, Token: j.Token, Revision: j.Revision}) != nil {
						close(leaseLost)
						cancel()
						return
					}
				}
			}
		}()
		input, _ := json.Marshal(map[string]any{"hash": j.Hash, "started": started, "plan": p, "targets": egress.Targets(), "delivery_targets": egress.DeliveryTargets(), "deep": j.Deep, "attempt": j.Attempt, "accepted": j.Accepted, "health_due": j.HealthDue})
		// Repair a broken helper once inside the original lease and deadline.
		// A valid measurement (including UNKNOWN) is immediately committed.
		for attempt := 0; attempt < 2; attempt++ {
			output, err := driver.exchange(job, input)
			var reply egress.Report
			if err == nil && json.Unmarshal(output, &reply) == nil && egress.ValidDriverReply(reply, p, j.Hash, started, egress.Now()) {
				r = reply
				break
			}
			driver.stop()
			r = egress.Report{Version: egress.Version, Hash: j.Hash, Started: started, Finished: egress.Now(), Code: "driver_session_failed"}
			if job.Err() != nil {
				select {
				case <-leaseLost:
					// No completed probe receipt exists; let the lease recover.
					return
				default:
				}
				break
			}
		}
	}
	if r.Finished == 0 {
		r.Finished = egress.Now()
	}
	j.Raw = nil
	if e := c.sendLeased(ctx, "complete", egress.Completion{Job: j, Report: r}); e != nil {
		log.Print("egress completion was not acknowledged")
	}
}

// One trusted helper and network namespace per slot. Every request launches a
// fresh capability-free core; the helper kills its whole cgroup and denies all
// egress before acknowledging a result. Failure destroys the slot and restarts it.
type driverSession struct {
	owner               context.Context
	helper, prefix, run string
	slot                int
	cmd                 *exec.Cmd
	input               io.WriteCloser
	responses           <-chan []byte
	closed              chan struct{}
	idleSince           time.Time
}

func (d *driverSession) start() error {
	d.run = egress.Hash([]byte(fmt.Sprint(os.Getpid(), d.slot, time.Now().UnixNano())))[:6]
	cmd := exec.CommandContext(d.owner, "/usr/bin/python3", d.helper, "--prefix", d.prefix, "--slot", fmt.Sprint(d.slot), "--run-id", d.run, "--serve")
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 3 * time.Second
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return err
	}
	if err = cmd.Start(); err != nil {
		input.Close()
		return err
	}
	responses := make(chan []byte, 1)
	closed := make(chan struct{})
	d.cmd = cmd
	d.input = input
	d.responses = responses
	d.closed = closed
	go func() {
		defer close(responses)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 65536), egress.MaxCompletionBytes+1) // include the framing newline
		for scanner.Scan() {
			body := append([]byte(nil), scanner.Bytes()...)
			select {
			case responses <- body:
			case <-closed:
				return
			}
		}
	}()
	return nil
}
func (d *driverSession) stop() {
	if d.cmd == nil {
		return
	}
	close(d.closed)
	d.input.Close()
	_ = d.cmd.Process.Kill()
	_ = d.cmd.Wait()
	clean(d.helper, d.prefix, d.slot, d.run)
	d.cmd = nil
	d.input = nil
	d.responses = nil
}

// Called only between jobs by the owning slot. Lowering concurrency must also
// release idle helpers and their namespace/GeoIP caches; otherwise all 31 warm
// slots retain memory and can prevent the resource governor from recovering.
// An in-flight measurement is allowed to finish under its existing deadline.
func (d *driverSession) idleAdmission(capacity int) bool {
	if d.slot <= capacity {
		return true
	}
	d.stop()
	return false
}

// idleRelease runs only between jobs, preserving active evidence collection.
func (d *driverSession) idleRelease(now time.Time, working bool) {
	if working {
		d.idleSince = time.Time{}
		return
	}
	if d.idleSince.IsZero() {
		d.idleSince = now
	}
	if now.Sub(d.idleSince) >= 30*time.Second {
		d.stop()
	}
}

func (d *driverSession) exchange(ctx context.Context, input []byte) ([]byte, error) {
	if d.cmd == nil {
		if err := d.start(); err != nil {
			return nil, err
		}
	}
	written := make(chan error, 1)
	writer := d.input
	go func() { _, err := writer.Write(append(input, '\n')); written <- err }()
	select {
	case err := <-written:
		if err != nil {
			d.stop()
			return nil, err
		}
	case <-ctx.Done():
		d.stop()
		return nil, ctx.Err()
	}
	select {
	case result, ok := <-d.responses:
		if !ok {
			d.stop()
			return nil, errors.New("driver closed")
		}
		return result, nil
	case <-ctx.Done():
		d.stop()
		return nil, ctx.Err()
	}
}

func run() error {
	socket := flag.String("socket", "/var/lib/config-repair/probe.sock", "local protected queue")
	helper := flag.String("helper", "/opt/config-repair/current/scripts/egress-probe.py", "trusted driver")
	prefix := flag.String("prefix", "cge", "isolated scope")
	lockPath := flag.String("lock-file", "/run/config-repair-egress.lock", "single supervisor")
	workers := flag.Int("workers", egress.MaxWorkers, "maximum concurrent isolated jobs")
	flag.Parse()
	if *workers < 1 || *workers > egress.MaxWorkers {
		return errors.New("invalid worker limit")
	}
	if os.Geteuid() != 0 || (*prefix != "cge" && *prefix != "cgt") {
		return errors.New("invalid supervisor environment")
	}
	lock, e := os.OpenFile(*lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("supervisor already running")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	clean(*helper, *prefix, 0, "")
	c := client{&http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	}}}}
	governor := resourceGovernor{current: resourceCapacity(*workers, sampleResources(*prefix)), changed: time.Now()}
	var capacityLimit atomic.Int32
	capacityLimit.Store(int32(governor.current))
	budget := resources.Budget{Directory: os.Getenv("CONFIG_REPAIR_RESOURCE_DIR")}
	polls := map[string]*worker.PollGate{"initial": {}, "followup": {}}
	var active atomic.Int32
	var wg sync.WaitGroup
	for slot := 1; slot <= *workers; slot++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			driver := &driverSession{owner: ctx, helper: *helper, prefix: *prefix, slot: slot}
			defer driver.stop()
			var claims uint64
			for ctx.Err() == nil {
				var j *egress.Job
				var release func()
				capacity := int(capacityLimit.Load())
				lane := investigationLane(slot, capacity, claims)
				if driver.idleAdmission(capacity) && polls[lane].Wait(ctx) {
					var ok bool
					release, ok = budget.Try(128 * 1024 * 1024)
					var err error
					if ok {
						err = c.call(ctx, "claim", map[string]string{"lane": lane}, &j)
					}
					polls[lane].Finish(time.Now(), err == nil && j != nil)
					if err != nil {
						j = nil
					}
				}
				if j == nil && release != nil {
					release()
					release = nil
				}
				if j != nil {
					driver.idleRelease(time.Now(), true)
					claims++
					active.Add(1)
					func() { defer release(); execute(ctx, c, driver, *j) }()
					active.Add(-1)
					continue
				}
				driver.idleRelease(time.Now(), false)
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}(slot)
	}
	notifySystemd("READY=1")
	defer notifySystemd("STOPPING=1")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		notifySystemd("WATCHDOG=1")
		capacityLimit.Store(int32(governor.update(resourceCapacity(*workers, sampleResources(*prefix)), time.Now())))
		_ = c.call(ctx, "status", map[string]any{"status": "running", "active": active.Load(), "code": fmt.Sprintf("capacity_%d", capacityLimit.Load())}, nil)
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	wg.Wait()
	clean(*helper, *prefix, 0, "")
	return nil
}
func main() {
	if e := run(); e != nil {
		log.Fatal(e)
	}
}
