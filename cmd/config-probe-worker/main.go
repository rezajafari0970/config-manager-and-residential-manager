// The privileged supervisor only accepts jobs from a protected local Unix
// socket. Untrusted configuration execution belongs exclusively to the sandbox.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/native"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/resources"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/side"
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

type client struct {
	http            *http.Client
	prefix, version string
	prepare         func([]byte) probe.Plan
	poll            *worker.PollGate
}

func (c client) call(ctx context.Context, path string, in, out any) error {
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "http://unix"+c.prefix+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("api_status_%d", res.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
	}
	return nil
}

func (c client) Claim(ctx context.Context) (*probe.Job, error) {
	if c.poll != nil && !c.poll.Wait(ctx) {
		return nil, nil
	}
	var j *probe.Job
	e := c.call(ctx, "/claim", nil, &j)
	if c.poll != nil {
		c.poll.Finish(time.Now(), e == nil && j != nil)
	}
	return j, e
}

type reservationDriver interface {
	Try(int64) (func(), bool)
}

type admittedQueue struct {
	client
	slot, maximum int
	governor      *resources.Controller
	budget        reservationDriver
	release       func()
	active        *atomic.Int32
}

func (q *admittedQueue) Claim(ctx context.Context) (*probe.Job, error) {
	capacity := q.governor.Capacity(q.maximum, time.Now())
	if q.slot > capacity {
		return nil, nil
	}
	var j *probe.Job
	retryDelay := time.Second
	if q.poll != nil {
		if !q.poll.Wait(ctx) {
			return nil, nil
		}
		defer func() {
			if j != nil {
				retryDelay = 0
			}
			q.poll.FinishAfter(time.Now(), retryDelay)
		}()
	}
	// Idle/waiting slots must not reserve memory or scan shared permits.
	release := func() {}
	if q.budget != nil {
		var ok bool
		probeBytes := int64(384 * 1024 * 1024)
		if q.prefix == "/side" {
			// Side runs one pinned core per identity. Its memory-limited sandbox
			// pool uses the same admission estimate as the isolated egress pool.
			probeBytes = 128 * 1024 * 1024
		}
		priority, shared := q.budget.(interface{ TryProbe(int64) (func(), bool) })
		if shared && q.prefix != "/side" {
			release, ok = priority.TryProbe(probeBytes)
		} else {
			release, ok = q.budget.Try(probeBytes)
			// Any available slot can represent this process. Idle/over-target
			// slots do not accumulate large reservations in the shared pool.
			// Competing due Side jobs may queue one fair permit for this PID
			// until half the configured slots are active, then borrow spare
			// capacity. Actual memory and pressure remain authoritative.
			if !ok && shared && q.prefix == "/side" && q.active != nil && q.active.Load() < int32(min(capacity, max(2, (q.maximum+1)/2))) {
				var ready bool
				if err := q.call(ctx, "/ready", nil, &ready); err != nil {
					return nil, err
				}
				if !ready {
					return nil, nil
				}
				release, ok = priority.TryProbe(probeBytes)
			}
		}
		if !ok {
			if q.prefix == "/side" {
				retryDelay = 150 * time.Millisecond
			}
			return nil, nil
		}
	}
	e := q.client.call(ctx, "/claim", nil, &j)
	if e != nil || j == nil {
		release()
		j = nil
		return nil, e
	}
	if q.active != nil {
		q.active.Add(1)
		q.release = func() { release(); q.active.Add(-1) }
	} else {
		q.release = release
	}
	return j, e
}

type helperResult struct {
	probe.Attempt
	Attempts []probe.Attempt `json:"attempts"`
}

func execute(ctx context.Context, c client, helper, core string, slot int, j probe.Job) {
	p := c.prepare(j.Raw)
	code := p.Code
	if repair.Digest(j.Raw) != j.Hash {
		code = "original_blob_unavailable"
		p.Candidates = nil
	}
	if j.Issue != "" {
		code = j.Issue
		p.Candidates = nil
	}
	if p.Kind == "" {
		p.Kind = j.Kind
	}
	p.Code = code
	r := probe.Result{Identity: j.Identity, Hash: j.Hash, Token: j.Token, Revision: j.Revision, Version: c.version, CoreSHA256: probe.CoreSHA256, Attempt: probe.Attempt{SHA256: j.Hash, Rule: "preparation", Core: "not_run", Connection: "not_run", Code: code}}
	if len(p.Candidates) > 0 {
		deadline := time.Duration(len(p.Candidates)*(155+3*j.Settings.TimeoutSeconds)) * time.Second
		if c.prefix == "/side" {
			// Bound one identity even when the parser produced several alternate
			// candidates. An interrupted or timed-out run is never a route verdict.
			deadline = min(deadline, 3*time.Minute)
		}
		jobCtx, cancel := context.WithTimeout(ctx, deadline)
		defer cancel()
		done := make(chan struct{})
		defer close(done)
		go func() {
			tick := time.NewTicker(20 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case <-jobCtx.Done():
					return
				case <-tick.C:
					leaseCtx, stop := context.WithTimeout(jobCtx, 10*time.Second)
					err := c.call(leaseCtx, "/renew", probe.Job{Identity: j.Identity, Hash: j.Hash, Token: j.Token, Revision: j.Revision}, nil)
					stop()
					if err != nil {
						cancel()
						return
					}
				}
			}
		}()
		input, _ := json.Marshal(map[string]any{"plan": p, "timeout": j.Settings.TimeoutSeconds})
		runID := repair.Digest([]byte(j.Token))[:6]
		command := exec.CommandContext(jobCtx, "/usr/bin/python3", helper, "--core", core, "--slot", fmt.Sprint(slot), "--run-id", runID)
		command.Stdin = bytes.NewReader(input)
		command.WaitDelay = 5 * time.Second
		var out bytes.Buffer
		command.Stdout = &out
		command.Stderr = io.Discard
		e := command.Run()
		var h helperResult
		if e == nil && json.Unmarshal(out.Bytes(), &h) == nil && h.Code != "" {
			r.Attempt = h.Attempt
			if r.Engine == "sing-box" {
				r.CoreSHA256 = native.NativeSHA
			}
			r.Attempts = h.Attempts
			for _, candidate := range p.Candidates {
				if candidate.SHA256 == h.SHA256 && (c.prefix != "/side" || h.Code == "passed") {
					r.Candidate = candidate.Config
					break
				}
			}
		} else {
			r.Core = "blocked"
			r.Code = "probe_infrastructure_error"
			if errors.Is(jobCtx.Err(), context.DeadlineExceeded) {
				r.Code = "probe_job_timeout"
			}
		}
		// The Side adapter closes its scoped kernel resources before writing
		// its receipt. Re-run recovery when the process exited abnormally.
		if c.prefix != "/side" || e != nil || h.Code == "" {
			cleanCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
			cleanup := exec.CommandContext(cleanCtx, "/usr/bin/python3", helper, "--cleanup-slot", fmt.Sprint(slot), "--cleanup-run", runID)
			cleanup.Stdout = io.Discard
			cleanup.Stderr = io.Discard
			_ = cleanup.Run()
			stop()
		}
	}
	completeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		e := c.call(completeCtx, "/complete", r, nil)
		if e == nil {
			return
		}
		log.Printf("probe completion deferred: %v", e)
		if e.Error() == "api_status_409" || e.Error() == "api_status_422" {
			return
		}
		select {
		case <-completeCtx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

type laneSettings struct {
	prefix, helper, lock string
	slots                int
}

func settingsForLane(name string) (laneSettings, error) {
	switch name {
	case "conversion":
		return laneSettings{"", "probe-one.py", "/run/config-repair-prober.lock", 8}, nil
	case "side":
		return laneSettings{"/side", "side-one.py", "/run/config-repair-side.lock", side.MaxWorkers}, nil
	default:
		return laneSettings{}, errors.New("unknown probe lane")
	}
}

func run() error {
	lane := flag.String("lane", "conversion", "independent queue: conversion or side")
	socket := flag.String("socket", "/var/lib/config-repair/probe.sock", "protected Unix queue socket")
	helper := flag.String("helper", "", "trusted sandbox driver")
	core := flag.String("core", "/opt/config-repair/core-26.11.9/xray", "pinned core")
	lockPath := flag.String("lock-file", "", "supervisor instance lock")
	flag.Parse()
	config, e := settingsForLane(*lane)
	if e != nil {
		return e
	}
	if *helper == "" {
		*helper = "/opt/config-repair/current/scripts/" + config.helper
	}
	if *lockPath == "" {
		*lockPath = config.lock
	}
	if os.Geteuid() != 0 {
		return errors.New("privileged sandbox supervisor required")
	}
	lock, e := os.OpenFile(*lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("probe supervisor already running")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	c := client{prefix: config.prefix, http: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	}}, Timeout: 30 * time.Second}, version: convert.Version, prepare: convert.Prepare, poll: &worker.PollGate{}}
	if config.prefix == "/side" {
		c.prepare = side.Prepare
	}
	slots := config.slots
	interval := time.Second
	maximumPoll := 2 * time.Second
	var governor resources.Controller
	if config.prefix == "/side" {
		governor.Policy = resources.NetworkProbes{}
		governor.RecoveryInterval = 2 * time.Second
		interval = 100 * time.Millisecond
		maximumPoll = 400 * time.Millisecond
	}

	status := func(state, code string, active int) {
		sc, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_ = c.call(sc, "/status", probe.WorkerStatus{Status: state, Code: code, Version: c.version, Active: active}, nil)
	}
	cleanCtx, cleanCancel := context.WithTimeout(ctx, 30*time.Second)
	clean := exec.CommandContext(cleanCtx, "/usr/bin/python3", *helper, "--cleanup")
	e = clean.Run()
	cleanCancel()
	if e != nil {
		return errors.New("probe_cleanup_failed")
	}
	status("starting", "sandbox_preflight", 0)
	checkCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	check := exec.CommandContext(checkCtx, "/usr/bin/python3", *helper, "--core", *core, "--self-test")
	e = check.Run()
	cancel()
	if e != nil {
		status("blocked", "sandbox_preflight_failed", 0)
		return errors.New("sandbox_preflight_failed")
	}
	var active atomic.Int32
	var wg sync.WaitGroup
	for slot := 1; slot <= slots; slot++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			q := &admittedQueue{client: c, slot: slot, maximum: slots, governor: &governor, active: &active, budget: resources.Budget{Directory: os.Getenv("CONFIG_REPAIR_RESOURCE_DIR")}}
			defer func() {
				if q.release != nil {
					q.release()
				}
			}()
			worker.RunSlot(ctx, q, func(ctx context.Context, slot int, j probe.Job) {
				defer func() { q.release(); q.release = nil }()
				execute(ctx, c, *helper, *core, slot, j)
			}, slot, interval, maximumPoll)
		}(slot)
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	status("running", "", 0)
	if config.prefix == "/side" {
		worker.NotifySystemd("READY=1")
		defer worker.NotifySystemd("STOPPING=1")
	}
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-tick.C:
			if config.prefix == "/side" {
				worker.NotifySystemd("WATCHDOG=1")
			}
			status("running", fmt.Sprintf("capacity_%d", governor.Capacity(slots, time.Now())), int(active.Load()))
		}
	}
}
func main() {
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
