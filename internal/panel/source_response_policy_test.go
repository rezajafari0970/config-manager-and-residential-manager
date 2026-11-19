package panel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHistoricalSourceResponsePublishesOnlyProvenMembers(t *testing.T) {
	s := testStore(t)
	source, j := addConversion(t, s, conversionSample)
	ctx := context.Background()
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	const disallowed = `{"outboundDetour":[{"protocol":"hysteria"}]}`
	raw := base64.StdEncoding.EncodeToString([]byte("json://" + base64.RawStdEncoding.EncodeToString([]byte(disallowed)) + "\n" + conversionSample))
	ref, err := s.vault.Put(ctx, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer s.vault.Release(ref.Hash)
	now := time.Now()
	_, err = s.db.Exec("INSERT OR REPLACE INTO responses(source_id,hash,size,created,expires) VALUES(?,?,?,?,?)", source, ref.Hash, ref.Size, now.UnixMilli(), now.Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := querySourceConversions(ctx, s.reader(), source, 0, true)
	if err != nil || len(rows) != 1 {
		t.Fatal(err, len(rows))
	}
	id := rows[0].ID
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, httptest.NewRequest("GET", app.origin+path, nil))
		return w
	}
	bySource := "/input/raw/" + source
	byID := "/output/raw/" + id + "?preview=1"
	if rr := get(bySource); rr.Code != 204 || rr.Body.Len() != 0 {
		t.Fatal("untested source returned content", rr.Code)
	}
	if rr := get(byID); rr.Code != 404 {
		t.Fatal("untested direct preview", rr.Code)
	}
	byJSON := "/output/json/" + id
	if rr := get(byJSON); rr.Code != 404 {
		t.Fatal("untested JSON preview", rr.Code)
	}
	var state string
	if err := s.db.QueryRow("SELECT state FROM conversion_jobs WHERE hash=?", rows[0].Hash).Scan(&state); err != nil || state != "running" {
		t.Fatal("preview changed claimed job", state, err)
	}
	countListed := func(want int) {
		t.Helper()
		rr := get("/api/conversions?healthy=1&source=" + source)
		var data struct{ Entries []Conversion }
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &data) != nil || len(data.Entries) != want {
			t.Fatal("unexpected verified output listing", rr.Code, len(data.Entries), want)
		}
	}
	countListed(0)
	if err := s.CompleteProbe(ctx, conversionResult(j, 0, true)); err != nil {
		t.Fatal(err)
	}
	countListed(1)
	if rr := get(byJSON); rr.Code != 200 || !json.Valid(rr.Body.Bytes()) {
		t.Fatal("verified JSON missing", rr.Code)
	}
	pinned := get("/api/prepared/export?single=1&id=" + id)
	if pinned.Code != 200 || !json.Valid(pinned.Body.Bytes()) || pinned.Header().Get("X-Export-Cycle") != "" {
		t.Fatal("direct template preview", pinned.Code)
	}
	var cursors int
	if err := s.db.QueryRow("SELECT count(*) FROM prepared_rotation").Scan(&cursors); err != nil || cursors != 0 {
		t.Fatal("fixed identity consumed shared rotation", cursors, err)
	}
	for _, url := range []string{bySource, byID, "/output/raw.txt"} {
		rr := get(url)
		if rr.Code != 200 || rr.Body.String() != conversionSample || rr.Header().Get("X-Config-Count") != "1" {
			t.Fatal("wrong verified raw", url, rr.Code)
		}
	}
	if _, err := s.ManageConfigs(ctx, ConfigBatch{Action: "disable", IDs: []string{id}}); err != nil {
		t.Fatal(err)
	}
	countListed(0)
	if rr := get(byJSON); rr.Code != 404 {
		t.Fatal("revoked JSON preview", rr.Code)
	}
	if rr := get(byID); rr.Code != 404 {
		t.Fatal("disabled bytes leaked through preview", rr.Code)
	}
	if rr := get(bySource); rr.Code != 204 || rr.Body.Len() != 0 {
		t.Fatal("revoked source member published", rr.Code)
	}
}
