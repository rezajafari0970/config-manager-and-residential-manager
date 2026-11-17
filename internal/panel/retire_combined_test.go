package panel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func retainedSnapshot(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, e := s.db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'smart_*' ORDER BY name")
	if e != nil {
		t.Fatal(e)
	}
	var names []string
	for rows.Next() {
		var n string
		if e = rows.Scan(&n); e != nil {
			t.Fatal(e)
		}
		names = append(names, n)
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	rows.Close()
	out := map[string]string{}
	for _, n := range names {
		cols, e := s.db.Query("SELECT name FROM pragma_table_info(?) WHERE name!='smart_excluded' ORDER BY cid", n)
		if e != nil {
			t.Fatal(e)
		}
		var fields []string
		for cols.Next() {
			var c string
			if e = cols.Scan(&c); e != nil {
				t.Fatal(e)
			}
			fields = append(fields, `"`+c+`"`)
		}
		cols.Close()
		rs, e := s.db.Query("SELECT " + strings.Join(fields, ",") + " FROM " + n)
		if e != nil {
			t.Fatal(e)
		}
		var records []string
		for rs.Next() {
			v := make([]any, len(fields))
			ptr := make([]any, len(v))
			for i := range v {
				ptr[i] = &v[i]
			}
			if e = rs.Scan(ptr...); e != nil {
				t.Fatal(e)
			}
			b, _ := json.Marshal(v)
			records = append(records, string(b))
		}
		if e = rs.Err(); e != nil {
			t.Fatal(e)
		}
		rs.Close()
		sort.Strings(records)
		out[n] = strings.Join(records, "\n")
	}
	return out
}
func TestRetireCombinedPreservesIndependentDataAndRemovesRoutes(t *testing.T) {
	s := testStore(t)
	newExportSource(t, s, "One", sourceURI(1), sourceURI(2))
	_, e := s.db.Exec(`CREATE TABLE smart_heads(id TEXT PRIMARY KEY);CREATE TABLE smart_cache(id TEXT PRIMARY KEY REFERENCES smart_heads(id),hash TEXT);CREATE TABLE smart_cache_members(id TEXT REFERENCES smart_cache(id));CREATE VIEW smart_ready AS SELECT * FROM smart_cache;INSERT INTO smart_heads VALUES('retired');INSERT INTO smart_cache VALUES('retired','fixture');INSERT INTO smart_cache_members VALUES('retired');ALTER TABLE sources ADD COLUMN smart_excluded INTEGER NOT NULL DEFAULT 1;CREATE INDEX sources_smart_excluded ON sources(smart_excluded);PRAGMA user_version=40;`)
	if e != nil {
		t.Fatal(e)
	}
	before := retainedSnapshot(t, s)
	for i := 0; i < 2; i++ {
		if e = s.migrateV41(); e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(before, retainedSnapshot(t, s)) {
			t.Fatal("independent data changed")
		}
	}
	var n int
	if e = s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name GLOB 'smart_*'").Scan(&n); e != nil || n != 0 {
		t.Fatal("retired schema retained", n, e)
	}
	if e = s.db.QueryRow("SELECT count(*) FROM pragma_table_info('sources') WHERE name='smart_excluded'").Scan(&n); e != nil || n != 0 {
		t.Fatal("retired source field", n, e)
	}
	app, e := NewServer(s, "http://127.0.0.1:18191")
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/smart", "/api/smart", "/api/smart/settings", "/assets/smart.js", "/smart-splash", "/smart-ads"} {
		rr := httptest.NewRecorder()
		app.Handler().ServeHTTP(rr, httptest.NewRequest("GET", app.origin+path, nil))
		if rr.Code != 404 {
			t.Fatal(path, rr.Code)
		}
	}
	configs, e := s.Conversions(context.Background(), 0, true)
	if e != nil || len(configs) != 2 {
		t.Fatal("ordinary output changed", e)
	}
	for _, v := range configs {
		if !v.Available {
			t.Fatal("ordinary output lost")
		}
	}
}
