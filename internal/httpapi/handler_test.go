package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aniket/axto/internal/keys"
	"github.com/aniket/axto/internal/mint"
)

func newTestHandler(t *testing.T, internalToken string) *Handler {
	t.Helper()
	store, err := keys.NewInMemoryStore()
	if err != nil {
		t.Fatalf("NewInMemoryStore: %v", err)
	}
	return NewHandler(mint.NewService(store), store, internalToken)
}

func TestHandleMint_RequiresAuthorization(t *testing.T) {
	h := newTestHandler(t, "s3cret")
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/internal/tokens:mint", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a bearer token, got %d", resp.StatusCode)
	}
}

func TestHandleMint_SucceedsWithValidRequest(t *testing.T) {
	h := newTestHandler(t, "s3cret")
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{
		"claims":     map[string]any{"sub": "zeropass://org/applications/app/service-accounts/sa"},
		"tokenType":  "jwt",
		"ttlSeconds": 300,
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/internal/tokens:mint", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var got mintResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Token == "" || got.JTI == "" {
		t.Fatalf("expected a populated token and jti, got %+v", got)
	}
}

func TestHandleMint_RejectsWrongToken(t *testing.T) {
	h := newTestHandler(t, "s3cret")
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/internal/tokens:mint", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer wrong")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with the wrong bearer token, got %d", resp.StatusCode)
	}
}

func TestHandleJWKS_IsPublicAndUnauthenticated(t *testing.T) {
	h := newTestHandler(t, "s3cret")
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with no Authorization header, got %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected exactly one key in the JWKS, got %d", len(jwks.Keys))
	}
}

func TestNewHandler_EmptyInternalTokenDisablesMint(t *testing.T) {
	h := newTestHandler(t, "")
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/internal/tokens:mint", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer ")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no internal token is configured, got %d", resp.StatusCode)
	}
}
