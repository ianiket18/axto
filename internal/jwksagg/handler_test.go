package jwksagg

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aniket/axto/internal/registry"
)

func TestHandleJWKS_IsPublicAndUnauthenticated(t *testing.T) {
	reg := registry.NewInMemoryRegistry()
	mustPublish(t, reg, "a", time.Now())

	h := NewHandler(NewAggregator(reg, time.Minute))
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected exactly one key, got %d", len(jwks.Keys))
	}
}
