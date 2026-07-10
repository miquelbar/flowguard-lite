package storage

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

type policyAnomalyRepository interface {
	SavePolicy(context.Context, *Policy) error
	SaveAnomaly(context.Context, *Anomaly) error
}

func TestKnownNoisyDeviceSuppression(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name string
		open func(*testing.T) policyAnomalyRepository
	}{
		{
			name: "sqlite",
			open: func(t *testing.T) policyAnomalyRepository {
				repo, err := NewSQLiteRepository(t.TempDir(), logger)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = repo.Close() })
				return repo
			},
		},
		{
			name: "duckdb",
			open: func(t *testing.T) policyAnomalyRepository {
				repo, err := NewDuckDBRepository(t.TempDir(), logger)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = repo.Close() })
				return repo
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := test.open(t)
			ctx := context.Background()
			if err := repo.SavePolicy(ctx, &Policy{
				Name:       "Known noisy infrastructure monitor",
				Scope:      "ip",
				Target:     "2001:db8:0:0:0:0:0:10",
				Suppressed: true,
			}); err != nil {
				t.Fatal(err)
			}
			// A lower-precedence alert-type policy must not re-enable the noisy IP.
			if err := repo.SavePolicy(ctx, &Policy{
				Name:  "Keep beacon alerts active",
				Scope: "alert_type", Target: "BEACONING",
			}); err != nil {
				t.Fatal(err)
			}

			now := time.Now().UTC()
			for _, anomalyType := range []string{"BEACONING", "PORT_FANOUT", "DEVICE_PROFILE_CHANGE"} {
				anomaly := newPolicyTestAnomaly("2001:db8::10", anomalyType, now)
				if err := repo.SaveAnomaly(ctx, anomaly); err != nil {
					t.Fatal(err)
				}
				if anomaly.Status != "silenced" {
					t.Fatalf("known noisy device %s was not silenced for %s: %s", anomaly.IP, anomalyType, anomaly.Status)
				}
			}

			unrelated := newPolicyTestAnomaly("2001:db8::11", "BEACONING", now)
			if err := repo.SaveAnomaly(ctx, unrelated); err != nil {
				t.Fatal(err)
			}
			if unrelated.Status != "active" {
				t.Fatalf("unrelated device was affected by exact-IP suppression: %s", unrelated.Status)
			}

			// The newest rule at the same scope can explicitly re-enable the device.
			if err := repo.SavePolicy(ctx, &Policy{
				Name:   "Monitor repaired infrastructure device",
				Scope:  "ip",
				Target: "2001:db8::10",
			}); err != nil {
				t.Fatal(err)
			}
			reEnabled := newPolicyTestAnomaly("2001:db8::10", "BEACONING", now.Add(time.Second))
			if err := repo.SaveAnomaly(ctx, reEnabled); err != nil {
				t.Fatal(err)
			}
			if reEnabled.Status != "active" {
				t.Fatalf("newest exact-IP rule did not re-enable device: %s", reEnabled.Status)
			}

			if err := repo.SavePolicy(ctx, &Policy{
				Name:       "Ignore approved backup destination",
				Scope:      "ip",
				Target:     "203.0.113.250",
				Suppressed: true,
			}); err != nil {
				t.Fatal(err)
			}
			ignoredDestination := newPolicyTestAnomaly("2001:db8::20", "NEW_DESTINATION", now.Add(2*time.Second))
			ignoredDestination.DestinationIP = "203.0.113.250"
			if err := repo.SaveAnomaly(ctx, ignoredDestination); err != nil {
				t.Fatal(err)
			}
			if ignoredDestination.Status != "silenced" {
				t.Fatalf("destination-scoped policy did not silence matching destination: %s", ignoredDestination.Status)
			}

			otherDestination := newPolicyTestAnomaly("2001:db8::21", "NEW_DESTINATION", now.Add(3*time.Second))
			otherDestination.DestinationIP = "203.0.113.251"
			if err := repo.SaveAnomaly(ctx, otherDestination); err != nil {
				t.Fatal(err)
			}
			if otherDestination.Status != "active" {
				t.Fatalf("destination-scoped policy affected unrelated destination: %s", otherDestination.Status)
			}
		})
	}
}

func newPolicyTestAnomaly(ip, anomalyType string, timestamp time.Time) *Anomaly {
	return &Anomaly{
		IP: ip, Type: anomalyType, Description: "policy regression",
		Severity: "high", Status: "active",
		CreatedAt: timestamp, UpdatedAt: timestamp,
	}
}
