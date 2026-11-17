package panel

import (
	"context"
	"errors"
	"fmt"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"io"
	"testing"
)

func TestOrdinaryMigrationsPreserveRawSettingsAndFenceOldWorkers(t *testing.T) {
	for _, tc := range []struct {
		schema  int
		old     string
		migrate func(*Store) error
	}{
		{18, "xray-26.7.28.template.v4", (*Store).migrateV19},
		{20, "xray-26.11.9.template.v6", (*Store).migrateV21},
		{23, "xray-26.11.9.template.v7", (*Store).migrateV24},
		{24, "xray-26.11.9.template.v8", (*Store).migrateV25},
	} {
		t.Run(fmt.Sprint(tc.schema), func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			newExportSource(t, s, "One", sourceURI(1), sourceURI(2))
			settings, _ := s.Settings(ctx)
			var hash string
			if e := s.db.QueryRow("SELECT hash FROM conversion_results LIMIT 1").Scan(&hash); e != nil {
				t.Fatal(e)
			}
			read := func() []byte {
				r, e := s.vault.Open(hash)
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				b, e := io.ReadAll(r)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			before := read()
			if _, e := s.db.Exec("UPDATE conversion_results SET version=?;UPDATE conversion_jobs SET version=?,token='legacy',lease_until=9999999999999", tc.old, tc.old); e != nil {
				t.Fatal(e)
			}
			if _, e := s.db.Exec(fmt.Sprintf("PRAGMA user_version=%d", tc.schema)); e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 2; i++ {
				if e := tc.migrate(s); e != nil {
					t.Fatal(e)
				}
			}
			rows, e := s.Conversions(ctx, 0, true)
			if e != nil {
				t.Fatal(e)
			}
			for _, r := range rows {
				if r.Available {
					t.Fatal("stale proof published")
				}
			}
			afterSettings, _ := s.Settings(ctx)
			if afterSettings != settings || string(read()) != string(before) {
				t.Fatal("raw/settings changed")
			}
			for i := 0; i < 2; i++ {
				j, e := s.ClaimProbe(ctx)
				if e != nil || j == nil {
					t.Fatal("new claim", e)
				}
				r := conversionResult(*j, 0, true)
				r.Version = tc.old
				if e = s.CompleteProbe(ctx, r); !errors.Is(e, ErrInvalid) {
					t.Fatal("old completion accepted", e)
				}
				r.Version = convert.Version
				if e = s.CompleteProbe(ctx, r); e != nil {
					t.Fatal(e)
				}
			}
			rows, e = s.Conversions(ctx, 0, true)
			if e != nil || len(rows) != 2 {
				t.Fatal(e)
			}
			for _, r := range rows {
				if !r.Available {
					t.Fatal("new proof unavailable")
				}
			}
		})
	}
}
