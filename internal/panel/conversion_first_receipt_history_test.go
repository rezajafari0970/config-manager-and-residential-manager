package panel

import (
	"context"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
)

func TestHistoricalOrdinaryReceiptRestoresCoverageOnly(t *testing.T) {
	for _, mode := range []string{"expired", "earlier-ledger", "later-ledger", "unbound-raw", "unbound-runtime", "reused", "wrong-version", "wrong-core", "payload-incomplete", "missing-checks", "invalid-json", "unmatched-owner", "ambiguous-identities"} {
		t.Run(mode, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			id, j := addConversion(t, s, sourceURI(208))
			if err := s.CompleteProbe(ctx, conversionResult(j, 0, true)); err != nil {
				t.Fatal(err)
			}
			var identity string
			if err := s.db.QueryRow("SELECT artifact_id FROM memberships WHERE raw_hash=?", j.Hash).Scan(&identity); err != nil {
				t.Fatal(err)
			}
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := s.db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			// Recreate v49's expired, retained receipt after loss of the source-owned
			// job. A new queue owner is waiting; no active input is publishable.
			exec("DELETE FROM conversion_first_assessed")
			commitProbeInputs(t, s, id, sourceURI(209))
			exec("DELETE FROM conversion_jobs WHERE hash=?", j.Hash)
			tested := time.Now().Add(-48 * time.Hour).UnixMilli()
			expired := tested + 3600000
			exec(`UPDATE conversion_receipts SET tested=?,valid_until=?,metadata=json_set(metadata,'$.tested',?) WHERE hash=?`, tested, expired, tested, j.Hash)
			switch mode {
			case "earlier-ledger", "later-ledger":
				prior := tested - 1000
				if mode == "later-ledger" {
					prior = tested + 1000
				}
				exec("INSERT INTO conversion_first_assessed VALUES(?,?,?,?)", identity, j.Hash, convert.Version, prior)
			case "reused":
				exec(`UPDATE conversion_receipts SET metadata=json_set(metadata,'$.reused_from_raw_sha256',?)`, j.Hash)
			case "unbound-raw":
				exec(`UPDATE conversion_receipts SET metadata=json_set(metadata,'$.raw_sha256','different')`)
			case "unbound-runtime":
				exec(`UPDATE conversion_receipts SET metadata=json_set(metadata,'$.runtime_sha256','different')`)
			case "wrong-version":
				exec(`UPDATE conversion_receipts SET version='older',metadata=json_set(metadata,'$.pipeline','older')`)
			case "wrong-core":
				exec(`UPDATE conversion_receipts SET metadata=json_set(metadata,'$.core_sha256','wrong')`)
			case "payload-incomplete":
				exec(`UPDATE conversion_receipts SET metadata=json_remove(metadata,'$.checks.payload_recheck')`)
			case "missing-checks":
				exec(`UPDATE conversion_receipts SET metadata=json_remove(metadata,'$.checks.https')`)
			case "invalid-json":
				exec(`UPDATE conversion_receipts SET metadata='{'`)
			case "unmatched-owner":
				exec(`UPDATE conversion_receipts SET hash=lower(hex(randomblob(32)))`)
			case "ambiguous-identities":
				exec(`INSERT INTO egress_owners(hash,identity,source) VALUES(?,'different-identity',?)`, j.Hash, id)
			}
			tx, err := s.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for range 2 {
				if err = rememberMeasuredOrdinaryReceipts(tx); err != nil {
					t.Fatal(err)
				}
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if mode == "expired" || mode == "earlier-ledger" || mode == "later-ledger" {
				expected := tested
				if mode == "earlier-ledger" {
					expected -= 1000
				}
				pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_assessed WHERE identity=? AND hash=? AND tested=? AND version=?", identity, j.Hash, expected, convert.Version)
				pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_backlog WHERE identity=?", identity)
			} else {
				pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_assessed WHERE identity=?", identity)
				pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_backlog WHERE identity=?", identity)
			}
			pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_receipts WHERE valid_until=?", expired)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_results WHERE hash=?", j.Hash)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_inputs WHERE hash=?", j.Hash)
		})
	}
}
