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

	store, err := NewManagedStore(ctx, reg, "instance-1", time.Minute)
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

func TestManagedStore_RotatePublishesNewKeyAndRetiresOld(t *testing.T) {
	reg := registry.NewInMemoryRegistry()
	ctx := context.Background()
	maxTokenTTL := 5 * time.Minute

	store, err := NewManagedStore(ctx, reg, "instance-1", maxTokenTTL)
	if err != nil {
		t.Fatalf("NewManagedStore: %v", err)
	}
	oldKey := store.Current()

	if err := store.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	newKey := store.Current()

	if newKey.ID == oldKey.ID {
		t.Fatal("expected Rotate to switch to a different key")
	}

	servableNow, err := reg.ListServable(ctx, time.Now())
	if err != nil {
		t.Fatalf("ListServable: %v", err)
	}
	if len(servableNow) != 2 {
		t.Fatalf("expected both the old (grace period) and new key to be servable, got %+v", servableNow)
	}

	servableAfterGrace, err := reg.ListServable(ctx, time.Now().Add(maxTokenTTL+time.Second))
	if err != nil {
		t.Fatalf("ListServable: %v", err)
	}
	if len(servableAfterGrace) != 1 || servableAfterGrace[0].KeyID != newKey.ID {
		t.Fatalf("expected only the new key to be servable after the grace period, got %+v", servableAfterGrace)
	}
}

func TestManagedStore_SigningNeverCallsRegistry(t *testing.T) {
	reg := &failingRegistryAfterInit{Registry: registry.NewInMemoryRegistry()}
	ctx := context.Background()

	store, err := NewManagedStore(ctx, reg, "instance-1", time.Minute)
	if err != nil {
		t.Fatalf("NewManagedStore: %v", err)
	}
	reg.failListServable = true

	// Current must be servable purely from local memory -- it must not
	// need to call the (now-failing) registry at all.
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
