package jwksagg

import (
	"encoding/json"
	"net/http"
)

// Handler serves the aggregator's combined JWKS over HTTP. It's the only
// endpoint this service exposes -- unlike the signer's httpapi.Handler,
// there is no mint endpoint here and nothing to authenticate, since this
// service never holds a private key.
type Handler struct {
	agg *Aggregator
}

func NewHandler(agg *Aggregator) *Handler {
	return &Handler{agg: agg}
}

func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	return mux
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := h.agg.JWKS(r.Context())
	if err != nil {
		http.Error(w, "failed to load keys", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}
