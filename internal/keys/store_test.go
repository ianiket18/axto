package keys

import "testing"

func TestInMemoryStore_CurrentAndJWKSAgree(t *testing.T) {
	store, err := NewInMemoryStore()
	if err != nil {
		t.Fatalf("NewInMemoryStore: %v", err)
	}

	current := store.Current()
	if current.ID == "" {
		t.Fatal("expected a non-empty key ID")
	}
	if current.PrivateKey == nil {
		t.Fatal("expected a non-nil private key")
	}

	jwks := store.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected exactly one published key, got %d", len(jwks.Keys))
	}
	published := jwks.Keys[0]
	if published.KeyID != current.ID {
		t.Fatalf("expected published kid %q to match current key %q", published.KeyID, current.ID)
	}
	if published.Algorithm != "ES256" {
		t.Fatalf("expected algorithm ES256, got %q", published.Algorithm)
	}
	if !published.IsPublic() {
		t.Fatal("expected the published JWKS entry to hold only the public key")
	}
}

func TestNewInMemoryStore_GeneratesDistinctKeysPerInstance(t *testing.T) {
	a, err := NewInMemoryStore()
	if err != nil {
		t.Fatalf("NewInMemoryStore: %v", err)
	}
	b, err := NewInMemoryStore()
	if err != nil {
		t.Fatalf("NewInMemoryStore: %v", err)
	}
	if a.Current().ID == b.Current().ID {
		t.Fatal("expected two independently generated stores to have different key IDs")
	}
}
