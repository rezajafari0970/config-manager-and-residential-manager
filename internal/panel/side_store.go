package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/side"
)

type SideJob struct {
	Identity string `json:"identity"`
	Hash     string `json:"hash"`
	Token    string `json:"token"`
	Kind     string `json:"kind"`
	Raw      []byte `json:"raw,omitempty"`
	Issue    string `json:"issue,omitempty"`
}
type SideResult struct {
	Identity  string            `json:"identity"`
	Hash      string            `json:"hash"`
	Token     string            `json:"token"`
	Code      string            `json:"code"`
	Evidence  map[string]string `json:"evidence,omitempty"`
	Candidate []byte            `json:"candidate,omitempty"`
}
type SideStats struct {
	OldestPending int64 `json:"oldest_pending"`
	Pending       int   `json:"pending"`
	Running       int   `json:"running"`
	Accepted      int   `json:"accepted"`
	Template      int   `json:"template"`
	Rejected      int   `json:"rejected"`
	Inconclusive  int   `json:"inconclusive"`
	Expired       int   `json:"expired"`
}

const sideLease = 2 * time.Minute
const sideAttempts = 3

// Probe work is shared across sources by identity. The preflight is read-only;
// the UPDATE and token predicate under the write reservation decide every grant.
func (s *Store) ClaimSide(ctx context.Context) (*SideJob, error) {
	release, err := s.admitClaim(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	due, err := s.SideReady(ctx)
	if err != nil || !due {
		return nil, err
	}
	tx, err := s.admittedTransaction(ctx, false)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE side_jobs SET token=token WHERE 0"); err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	if err = settleSideLeases(ctx, tx.Tx, now); err != nil {
		return nil, err
	}
	due, err = sideReadyAt(ctx, tx.Tx, now)
	if err != nil {
		return nil, err
	}
	if !due {
		return nil, tx.Commit()
	}
	j, size, fresh, err := selectSideGrant(ctx, tx.Tx, now)
	if err != nil {
		return nil, err
	}
	if j == nil {
		return nil, tx.Commit()
	}
	j.Token = randomToken()
	res, err := tx.ExecContext(ctx, `UPDATE side_jobs SET attempts=attempts+1,token=?,lease_until=? WHERE identity=?
 AND EXISTS(SELECT 1 FROM side_work w WHERE w.identity=side_jobs.identity)`, j.Token, now+sideLease.Milliseconds(), j.Identity)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, sideTurnKey, fresh); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	release()
	if size > repair.MaxBytes {
		j.Issue = "input_size_limit"
		return j, nil
	}
	raw, err := s.sideRaw(j.Hash)
	if err != nil {
		j.Issue = "input_unavailable"
	} else {
		j.Raw = raw
	}
	return j, nil
}

func (s *Store) sideRaw(hash string) ([]byte, error) {
	body, err := s.openExportBlob(hash)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, repair.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > repair.MaxBytes || repair.Digest(raw) != hash {
		return nil, ErrInvalid
	}
	return raw, nil
}

const sideGrant = `identity=? AND raw_hash=? AND token=? AND token!='' AND lease_until>` + sideNow + `
 AND EXISTS(SELECT 1 FROM side_work w WHERE w.identity=side_jobs.identity)`

func (s *Store) updateSideGrant(ctx context.Context, statement string, args ...any) error {
	tx, err := s.admittedTransaction(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (s *Store) RenewSide(ctx context.Context, j SideJob) error {
	return s.updateSideGrant(ctx, "UPDATE side_jobs SET lease_until="+sideNow+"+? WHERE "+sideGrant, sideLease.Milliseconds(), j.Identity, j.Hash, j.Token)
}

func (s *Store) DeferSide(ctx context.Context, j SideJob, code string) error {
	if !safeCode(code) {
		return ErrInvalid
	}
	now := time.Now().UnixMilli()
	// A run without a measurement never becomes evidence of a service failure.
	// Put fresh inputs ahead of retry work. Bound failures of the local worker.
	return s.updateSideGrant(ctx, `UPDATE side_jobs SET token='',lease_until=0,code=?,
 state=CASE WHEN attempts>=? THEN 'inconclusive' ELSE 'pending' END,
 finished=CASE WHEN attempts>=? THEN ? ELSE 0 END,next_run=?+min(60,attempts*5)*1000 WHERE `+sideGrant,
		code, sideAttempts, sideAttempts, now, now, j.Identity, j.Hash, j.Token)
}

var sideServices = [...]string{"google", "facebook", "instagram", "twitter", "telegram", "upload", "download", "stability", "cloudflare", "warp"}

func validSideEvidence(r SideResult) bool {
	if !safeCode(r.Code) || len(r.Evidence) > 40 || !validDigest(r.Hash) || r.Identity == "" || r.Token == "" {
		return false
	}
	for key, value := range r.Evidence {
		if !safeCode(key) || !safeCode(value) {
			return false
		}
	}
	passed := true
	for _, k := range sideServices {
		if r.Evidence[k] != "passed" {
			passed = false
		}
	}
	if r.Code != "passed" {
		return len(r.Candidate) == 0 && (!passed || r.Evidence["raw_checks"] == "failed")
	}
	return passed && len(r.Candidate) > 0 && len(r.Candidate) <= repair.MaxBytes &&
		r.Evidence["raw_checks"] == "passed" && r.Evidence["raw_input_sha256"] == r.Hash && validDigest(r.Evidence["raw_runtime_sha256"]) &&
		r.Evidence["side_version"] == "side_v1" && (r.Evidence["warp_mode"] == "on" || r.Evidence["warp_mode"] == "plus") &&
		r.Evidence["upload_bytes"] == "131072" && r.Evidence["download_bytes"] == "262144" && r.Evidence["stability_samples"] == "3" &&
		r.Evidence["candidate_sha256"] == repair.Digest(r.Candidate)
}

// Validate that the reported bytes are one of this input's deterministic
// templates. A worker cannot attach a passing receipt from another candidate.
func (s *Store) sideCandidate(ctx context.Context, r SideResult) (hash, engine string, err error) {
	raw, err := s.sideRaw(r.Hash)
	if err != nil {
		return "", "", err
	}
	if protocolpolicy.Disabled("", r.Candidate) {
		return "", "", ErrInvalid
	}
	plan := side.Prepare(raw)
	if plan.RawCandidate == nil || plan.RawCandidate.SHA256 != r.Evidence["raw_runtime_sha256"] {
		return "", "", ErrInvalid
	}
	for _, c := range plan.Candidates {
		if c.SHA256 != r.Evidence["candidate_sha256"] || !bytes.Equal(c.Config, r.Candidate) {
			continue
		}
		engine = c.Engine
		if engine == "" {
			engine = "xray"
		}
		if engine != "xray" && engine != "sing-box" || r.Evidence["engine"] != "" && r.Evidence["engine"] != engine {
			return "", "", ErrInvalid
		}
		ref, err := s.vault.Put(ctx, bytes.NewReader(r.Candidate))
		return ref.Hash, engine, err
	}
	return "", "", ErrInvalid
}

func (s *Store) CompleteSide(ctx context.Context, r SideResult) error {
	if !validSideEvidence(r) {
		return ErrInvalid
	}
	b, err := json.Marshal(r.Evidence)
	if err != nil {
		return err
	}
	state := "rejected"
	var candidate, engine string
	if r.Code == "passed" {
		state = "accepted"
		candidate = r.Evidence["candidate_sha256"]
	}
	// An HTTP response can be lost after the commit. Replaying that same
	// terminal receipt is harmless, even if ordinary retention has since elapsed.
	var repeated bool
	err = s.workerReader().QueryRowContext(ctx, `SELECT state=? AND code=? AND evidence=? AND candidate_hash=? AND last_token=? FROM side_jobs WHERE identity=? AND raw_hash=?`,
		state, r.Code, string(b), candidate, r.Token, r.Identity, r.Hash).Scan(&repeated)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil || repeated {
		return err
	}
	if state == "accepted" {
		candidate, engine, err = s.sideCandidate(ctx, r)
		if err != nil {
			return err
		}
		defer s.vault.Release(candidate)
	}
	now := time.Now().UnixMilli()
	return s.updateSideGrant(ctx, `UPDATE side_jobs SET state=?,finished=?,code=?,evidence=?,candidate_hash=?,engine=?,last_token=token,token='',lease_until=0 WHERE `+sideGrant,
		state, now, r.Code, string(b), candidate, engine, r.Identity, r.Hash, r.Token)
}

func (s *Store) SideCounts(ctx context.Context) (SideStats, error) {
	var v SideStats
	now := readStamp(ctx)
	err := s.read(ctx).QueryRowContext(ctx, `WITH work AS MATERIALIZED (SELECT lease_until,queued_at FROM side_work), exports AS MATERIALIZED (SELECT engine FROM side_export_inputs)
 SELECT (SELECT coalesce(min(queued_at),0) FROM work WHERE lease_until<=?),(SELECT count(*) FROM work WHERE lease_until<=?),(SELECT count(*) FROM work WHERE lease_until>?),
 (SELECT count(*) FROM exports),(SELECT count(*) FROM exports WHERE engine='xray'),
 (SELECT count(*) FROM side_jobs WHERE state='rejected' AND expires>?),
 (SELECT count(*) FROM side_jobs WHERE state='inconclusive' AND expires>?),
 (SELECT identities FROM side_metrics WHERE id=1)-(SELECT count(*) FROM side_jobs WHERE expires>?)`, now, now, now, now, now, now).
		Scan(&v.OldestPending, &v.Pending, &v.Running, &v.Accepted, &v.Template, &v.Rejected, &v.Inconclusive, &v.Expired)
	return v, err
}
