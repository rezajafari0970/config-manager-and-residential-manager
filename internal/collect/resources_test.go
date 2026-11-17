package collect

import (
	"bytes"
	"context"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/blob"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/resources"
	"testing"
)

type lowMemorySensor struct{}

func (lowMemorySensor) Sample() resources.Sample { return resources.Sample{AvailableKB: 100} }
func TestResourcePressurePreservesActiveCollection(t *testing.T) {
	vault, e := blob.New(t.TempDir(), bytes.Repeat([]byte{3}, 32))
	if e != nil {
		t.Fatal(e)
	}
	repo := &abandonedHandoffRepo{job: Job{ID: "same-source", Token: "new-token", Revision: 2}}
	engine := NewEngine(repo, vault, nil)
	cancelled := false
	engine.active[repo.job.ID] = func() { cancelled = true }
	engine.SetResourceController(&resources.Controller{Sensor: lowMemorySensor{}})
	engine.dispatch(context.Background())
	if cancelled || len(repo.abandoned) != 0 || engine.Capacity() != 0 || engine.BlockedReason() != "resource_pressure" {
		t.Fatal("pressure mutated active job")
	}
}
