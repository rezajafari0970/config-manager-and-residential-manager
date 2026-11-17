package panel

import (
	"context"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestEgressLeaseScopeAfterMembershipChange(t *testing.T) {
	cases := []struct {
		name, mutation string
		allowed        bool
	}{
		{"current", "", true},
		{"unowned", "DELETE FROM memberships", false},
		{"retained", "UPDATE egress_jobs SET ever_accepted=1; DELETE FROM memberships", true},
		{"quarantine_followup", "INSERT INTO egress_iran_guard(identity,state,first_seen) SELECT identity,'QUARANTINED',1 FROM egress_unique; DELETE FROM memberships", true},
		{"blocked", "INSERT INTO egress_iran_guard(identity,state,first_seen) SELECT identity,'BLOCKED',1 FROM egress_unique", false},
		{"excluded", "INSERT INTO input_exclusions(identity,at,hash,manual) SELECT identity,1,hash,1 FROM egress_unique", false},
		{"not_representative", "DELETE FROM egress_unique", false},
		{"paused", "UPDATE egress_jobs SET paused=1", false},
	}
	for _, c := range cases {
		for _, operation := range []string{"renew", "complete"} {
			t.Run(c.name+"/"+operation, func(t *testing.T) {
				s := testStore(t)
				ctx := context.Background()
				newExportSource(t, s, "lease-scope", sourceURI(753))
				j, err := s.ClaimEgress(ctx)
				if err != nil || j == nil {
					t.Fatal(j, err)
				}
				if c.mutation != "" {
					if _, err = s.db.Exec(c.mutation); err != nil {
						t.Fatal(err)
					}
				}
				if operation == "renew" {
					err = s.RenewEgress(ctx, *j)
				} else {
					err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)})
				}
				if c.allowed && err != nil || !c.allowed && err != ErrConflict {
					t.Fatal("scope admission changed", c.allowed, err)
				}
			})
		}
	}
}
