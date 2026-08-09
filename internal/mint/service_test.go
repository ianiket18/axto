package mint

import (
	"context"
	"errors"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/aniket/axto/internal/keys"
)

func newTestService(t *testing.T) (*Service, keys.Store) {
	t.Helper()
	store, err := keys.NewInMemoryStore()
	if err != nil {
		t.Fatalf("NewInMemoryStore: %v", err)
	}
	return NewService(store, 0), store
}

func TestMint_ProducesAVerifiableToken(t *testing.T) {
	svc, store := newTestService(t)

	result, err := svc.Mint(context.Background(), Request{
		Claims: map[string]any{
			"sub":    "zeropass://org/applications/app/service-accounts/sa",
			"org_id": "org-123",
		},
		TokenType: "jwt",
		TTL:       5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if result.Token == "" || result.JTI == "" {
		t.Fatalf("expected a populated token and jti, got %+v", result)
	}

	parsed, err := jwt.ParseSigned(result.Token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}

	var claims map[string]any
	if err := parsed.Claims(store.Current().PrivateKey.Public(), &claims); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	if claims["sub"] != "zeropass://org/applications/app/service-accounts/sa" {
		t.Fatalf("expected sub claim to survive signing, got %+v", claims)
	}
	if claims["org_id"] != "org-123" {
		t.Fatalf("expected org_id claim to survive signing, got %+v", claims)
	}
	if claims["jti"] != result.JTI {
		t.Fatalf("expected jti claim %q to match returned jti %q", claims["jti"], result.JTI)
	}
}

func TestMint_RejectsUnsupportedTokenType(t *testing.T) {
	svc, _ := newTestService(t)

	_, err := svc.Mint(context.Background(), Request{
		Claims:    map[string]any{"sub": "x"},
		TokenType: "dpop",
		TTL:       time.Minute,
	})
	if !errors.Is(err, ErrUnsupportedTokenType) {
		t.Fatalf("expected ErrUnsupportedTokenType, got %v", err)
	}
}

func TestMint_RejectsNonPositiveTTL(t *testing.T) {
	svc, _ := newTestService(t)

	if _, err := svc.Mint(context.Background(), Request{
		Claims:    map[string]any{"sub": "x"},
		TokenType: "jwt",
		TTL:       0,
	}); err == nil {
		t.Fatal("expected a zero TTL to be rejected")
	}
}

func TestMint_RejectsTTLBeyondConfiguredMax(t *testing.T) {
	store, err := keys.NewInMemoryStore()
	if err != nil {
		t.Fatalf("NewInMemoryStore: %v", err)
	}
	svc := NewService(store, time.Minute)

	_, err = svc.Mint(context.Background(), Request{
		Claims:    map[string]any{"sub": "x"},
		TokenType: "jwt",
		TTL:       time.Hour,
	})
	if !errors.Is(err, ErrTTLExceedsMax) {
		t.Fatalf("expected ErrTTLExceedsMax, got %v", err)
	}
}

func TestMint_AllowsTTLAtOrBelowConfiguredMax(t *testing.T) {
	store, err := keys.NewInMemoryStore()
	if err != nil {
		t.Fatalf("NewInMemoryStore: %v", err)
	}
	svc := NewService(store, time.Minute)

	if _, err := svc.Mint(context.Background(), Request{
		Claims:    map[string]any{"sub": "x"},
		TokenType: "jwt",
		TTL:       time.Minute,
	}); err != nil {
		t.Fatalf("expected a TTL equal to the max to be accepted, got %v", err)
	}
}
