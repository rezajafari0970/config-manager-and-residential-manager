package panel

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestPinnedResidentialRotationConcurrentReaders(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "parallel-next", sourceURI(95), sourceURI(96))
	for range 2 {
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil {
			t.Fatal("expected job", err)
		}
		if err := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
			t.Fatal(err)
		}
	}
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	base := egressModule{app}.links()["next.json"]
	head := exportRequest(t, handler, "HEAD", base)
	if head.Code != 200 || head.Header().Get("X-Egress-Generation") == "" {
		t.Fatal("unavailable generation", head.Code)
	}
	url := base + "?generation=" + head.Header().Get("X-Egress-Generation")
	const readers = 12
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, readers)
	for range readers {
		go func() { <-start; responses <- exportRequest(t, handler, "GET", url) }()
	}
	close(start)
	counts := map[string]int{}
	for range readers {
		rr := <-responses
		if rr.Code != 200 || rr.Header().Get("X-Config-Count") != "1" {
			t.Errorf("stable pinned rotation returned HTTP %d", rr.Code)
			continue
		}
		counts[rr.Header().Get("X-Content-SHA256")]++
	}
	if len(counts) != 2 {
		t.Fatalf("rotated %d distinct configs", len(counts))
	}
	for _, count := range counts {
		if count != readers/2 {
			t.Errorf("got %d turns for one config, want %d", count, readers/2)
		}
	}
}
