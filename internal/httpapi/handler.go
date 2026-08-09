// Package httpapi exposes Axto's two endpoints: an internal Mint call and
// a public JWKS document. There is deliberately no third endpoint.
package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aniket/axto/internal/keys"
	"github.com/aniket/axto/internal/mint"
)

type Handler struct {
	mint          *mint.Service
	keys          keys.Store
	internalToken string
}

// NewHandler builds the HTTP handler. internalToken gates the Mint
// endpoint -- a placeholder for real service-to-service auth. An empty
// internalToken disables Mint entirely rather than leaving it open.
func NewHandler(mintSvc *mint.Service, keyStore keys.Store, internalToken string) *Handler {
	return &Handler{mint: mintSvc, keys: keyStore, internalToken: internalToken}
}

func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/tokens:mint", h.handleMint)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	return mux
}

type mintRequest struct {
	Claims     map[string]any `json:"claims"`
	TokenType  string         `json:"tokenType"`
	TTLSeconds int            `json:"ttlSeconds"`
}

type mintResponse struct {
	Token     string    `json:"token"`
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (h *Handler) handleMint(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req mintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.TTLSeconds <= 0 {
		http.Error(w, "ttlSeconds must be positive", http.StatusBadRequest)
		return
	}

	result, err := h.mint.Mint(r.Context(), mint.Request{
		Claims:    req.Claims,
		TokenType: req.TokenType,
		TTL:       time.Duration(req.TTLSeconds) * time.Second,
	})
	if err != nil {
		if errors.Is(err, mint.ErrUnsupportedTokenType) || errors.Is(err, mint.ErrTTLExceedsMax) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mintResponse{
		Token:     result.Token,
		JTI:       result.JTI,
		ExpiresAt: result.ExpiresAt,
	})
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.keys.JWKS())
}

func (h *Handler) authorized(r *http.Request) bool {
	if h.internalToken == "" {
		return false
	}
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	token := strings.TrimPrefix(auth, prefix)
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.internalToken)) == 1
}
