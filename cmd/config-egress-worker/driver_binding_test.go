package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestBrokenDriverFrameRepairedInsideOriginalLease(t *testing.T) {
	for _, tc := range []struct{ name, first, repeat, code string }{
		{"empty object", "{}", "valid", "measured"},
		{"wrong hash", "wrong", "valid", "measured"},
		{"unbound clock", "stale", "valid", "measured"},
		{"missing attempts", "no-attempts", "valid", "measured"},
		{"empty measurement", "no-samples", "valid", "measured"},
		{"unbound variant", "bad-variant", "valid", "measured"},
		{"one variant measured", "one-variant", "valid", "measured"},
		{"preflight veto", "valid-veto", "valid", "direct_route_not_qualified"},
		{"large multi-attempt reply", "large", "large", "measured"},
		{"two null replies", "null", "null", "driver_session_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			helper := filepath.Join(dir, "driver.py")
			body := `import json,os,sys,time
if '--cleanup' in sys.argv:sys.exit(0)
marker=__file__+'.runs'
for line in sys.stdin:
 req=json.loads(line)
 mode=` + "'" + tc.first + `' if not os.path.exists(marker) else '` + tc.repeat + `'
 with open(marker,'a') as f:f.write('x')
 if mode in ('{}','null'):print(mode,flush=True);continue
 core='xray-26.11.9'
 checks=[{'name':v['name'],'hash':v['hash'],'runtime_hash':v['hash'],'core':True} for v in req['plan']['variants']]
 samples=[{'domain':'www.google.com','variant':v['name'],'wave':1,'at':req['started'],'code':'network_failure'} for v in checks]
 report={'version':'` + egress.Version + `','hash':req['hash'],'started':req['started'],'finished':int(time.time()*1000),'code':'measured','core':core,'core_sha':'` + egress.Cores["xray-26.11.9"] + `','checks':checks,'samples':samples,'waves':2,'attempts':[{'core':core,'code':'measured'}]}
 if mode=='bad-variant':checks[0]['hash']='different'
 if mode=='one-variant':samples.pop()
 if mode=='valid-veto':report.update(code='direct_route_not_qualified',checks=[],samples=[],attempts=[{'core':core,'code':'direct_route_not_qualified'}])
 if mode=='large':
  providers=[{'name':'fixture-'+str(i),'lineage':'fixture-'+str(i),'kind':'database','dataset':'a'*64,'released_at':req['started']-60000,'country':'TR'} for i in range(8)]
  geo={'version':'test','at':req['started'],'providers':providers}
  report['evidence']=[{'version':report['version'],'hash':req['hash'],'started':req['started'],'finished':report['finished'],'core':core,'core_sha':report['core_sha'],'checks':checks,'waves':2,'samples':[dict(samples[i%2],geo=geo,nonce=f'{i:032x}',connection=f'{i:032x}') for i in range(210)]} for _ in range(4)]
  assert (1<<20)<len(json.dumps(report))<(3<<20)
 if mode=='wrong':report['hash']='other'
 if mode=='stale':report['started']-=5000
 if mode=='no-attempts':report.pop('attempts')
 if mode=='no-samples':report.pop('samples')
 print(json.dumps(report),flush=True)
`
			if err := os.WriteFile(helper, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			driver := &driverSession{owner: ctx, helper: helper, prefix: "cgt", slot: 1}
			defer driver.stop()
			raw := []byte("vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=example.com")
			j := egress.Job{Raw: raw, Hash: egress.Hash(raw), Token: "only-lease", Revision: 2}
			completions := 0
			client := client{&http.Client{Transport: receiptTransport(func(r *http.Request) (*http.Response, error) {
				var c egress.Completion
				if r.URL.Path != "/egress/complete" || json.NewDecoder(r.Body).Decode(&c) != nil {
					t.Fatal("unexpected request")
				}
				if c.Job.Token != j.Token || c.Job.Revision != j.Revision || c.Report.Hash != j.Hash || c.Report.Code != tc.code {
					t.Errorf("wrong completion code or binding: %q", c.Report.Code)
				}
				completions++
				return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
			})}}
			execute(ctx, client, driver, j)
			runs, err := os.ReadFile(helper + ".runs")
			expectedRuns := 2
			if tc.first == "valid-veto" || tc.first == "large" {
				expectedRuns = 1
			}
			if err != nil || len(runs) != expectedRuns || completions != 1 {
				t.Fatalf("driver received %d requests; %d completions (%v)", len(runs), completions, err)
			}
		})
	}
}

func TestUnavailableInputDoesNotMasqueradeAsUnsupportedPlan(t *testing.T) {
	raw := []byte("this synthetic format has no driver")
	for _, tc := range []struct{ name, hash, issue, want string }{
		{"unsupported", egress.Hash(raw), "", "driver_unavailable"},
		{"unbound input", egress.Hash([]byte("other")), "", "input_unavailable"},
		{"missing in store", egress.Hash(raw), "input_unavailable", "input_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := egress.Job{Raw: raw, Hash: tc.hash, Token: "test", Issue: tc.issue}
			completed := false
			client := client{&http.Client{Transport: receiptTransport(func(req *http.Request) (*http.Response, error) {
				var c egress.Completion
				if json.NewDecoder(req.Body).Decode(&c) != nil || req.URL.Path != "/egress/complete" || c.Report.Code != tc.want || len(c.Report.Attempts) != 0 {
					t.Fatalf("unexpected completion %q", c.Report.Code)
				}
				completed = true
				return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
			})}}
			execute(context.Background(), client, nil, j)
			if !completed {
				t.Fatal("no completion")
			}
		})
	}
}
