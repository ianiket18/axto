package keys

import (
	"context"
	"testing"
	"time"

	"github.com/aniket/axto/internal/registry"
)

func TestNewManagedStore_PublishesBeforeSigning(t *testing.T) {
	reg := registry.NewInMemoryRegistry()
	ctx := context.Background()

	store, err := NewManagedStore(ctx, reg, "instance-1", time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewManagedStore: %v", err)
	}

	current := store.Current()
	recs, err := reg.ListServable(ctx, time.Now())
	if err != nil {
		t.Fatalf("ListServable: %v", err)
	}
	if len(recs) != 1 || recs[0].KeyID != current.ID {
		t.Fatalf("expected the current key to already be published, got %+v", recs)
	}
}

func TestTick_BeforeHalfLifeDoesNothing(t *testing.T) {
	reg := registry.NewInMemoryRegistry()
	ctx := context.Background()

	store, err := NewManagedStore(ctx, reg, "instance-1", time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewManagedStore: %v", err)
	}
	if err := store.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	recs, err := reg.ListServable(ctx, time.Now())
	if err != nil {
		t.Fatalf("ListServable: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected no new key staged before half life, got %+v", recs)
	}
}

func TestTick_PastHalfLifeStagesWithoutSwitchingCurrent(t *testing.T) {
	reg := registry.NewInMemoryRegistry()
	ctx := context.Background()
	keyLifetime := 10 * time.Millisecond

	store, err := NewManagedStore(ctx, reg, "instance-1", keyLifetime, time.Minute)
	if err != nil {
		t.Fatalf("NewManagedStore: %v", err)
	}
	original := store.Current()

	time.Sleep(keyLifetime/2 + time.Millisecond)
	if err := store.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if store.Current().ID != original.ID {
		t.Fatal("expected staging to not switch the signing key yet")
	}

	recs, err := reg.ListServable(ctx, time.Now())
	if err != nil {
		t.Fatalf("ListServable: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected the staged key to be published alongside the current one, got %+v", recs)
	}
}

func TestTick_PastExpiryActivatesStagedKeyAndRetiresOld(t *testing.T) {
	reg := registry.NewInMemoryRegistry()
	ctx := context.Background()
	keyLifetime := 10 * time.Millisecond
	maxTokenTTL := time.Minute

	store, err := NewManagedStore(ctx, reg, "instance-1", keyLifetime, maxTokenTTL)
	if err != nil {
		t.Fatalf("NewManagedStore: %v", err)
	}
	original := store.Current()

	time.Sleep(keyLifetime + time.Millisecond)
	if err := store.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	newKey := store.Current()
	if newKey.ID == original.ID {
		t.Fatal("expected the expired key to be replaced")
	}

	servableNow, err := reg.ListServable(ctx, time.Now())
	if err != nil {
		t.Fatalf("ListServable: %v", err)
	}
	if len(servableNow) != 2 {
		t.Fatalf("expected both the retired (grace period) and new key to be servable, got %+v", servableNow)
	}

	servableAfterGrace, err := reg.ListServable(ctx, time.Now().Add(maxTokenTTL+time.Second))
	if err != nil {
		t.Fatalf("ListServable: %v", err)
	}
	if len(servableAfterGrace) != 1 || servableAfterGrace[0].KeyID != newKey.ID {
		t.Fatalf("expected only the new key to be servable after the grace period, got %+v", servableAfterGrace)
	}
}

func TestTick_IsSelfHealingAcrossASkippedInterval(t *testing.T) {
	// If Tick isn't called for long enough that the current key is
	// already past its full lifetime, one Tick call should both stage
	// and activate in the same pass rather than requiring two calls.
	reg := registry.NewInMemoryRegistry()
	ctx := context.Background()
	keyLifetime := 10 * time.Millisecond

	store, err := NewManagedStore(ctx, reg, "instance-1", keyLifetime, time.Minute)
	if err != nil {
		t.Fatalf("NewManagedStore: %v", err)
	}
	original := store.Current()

	time.Sleep(keyLifetime * 3)
	if err := store.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if store.Current().ID == original.ID {
		t.Fatal("expected a single Tick to stage and activate when both thresholds were already passed")
	}
}

func TestManagedStore_SigningNeverCallsRegistry(t *testing.T) {
	reg := &failingRegistryAfterInit{Registry: registry.NewInMemoryRegistry()}
	ctx := context.Background()

	store, err := NewManagedStore(ctx, reg, "instance-1", time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewManagedStore: %v", err)
	}
	reg.failListServable = true

	for i := 0; i < 3; i++ {
		if store.Current().PrivateKey == nil {
			t.Fatal("expected Current to return a usable key without touching the registry")
		}
	}
}

type failingRegistryAfterInit struct {
	registry.Registry
	failListServable bool
}

func (f *failingRegistryAfterInit) ListServable(ctx context.Context, asOf time.Time) ([]registry.PublicKeyRecord, error) {
	if f.failListServable {
		panic("ListServable should not be called by ManagedStore.Current")
	}
	return f.Registry.ListServable(ctx, asOf)
}
