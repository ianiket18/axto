package main

import (
	"log"
	"net/http"
	"os"

	"github.com/aniket/axto/internal/httpapi"
	"github.com/aniket/axto/internal/keys"
	"github.com/aniket/axto/internal/mint"
)

func main() {
	internalToken := os.Getenv("AXTO_INTERNAL_TOKEN")
	if internalToken == "" {
		log.Fatal("AXTO_INTERNAL_TOKEN must be set (shared secret gating the Mint endpoint)")
	}

	keyStore, err := keys.NewInMemoryStore()
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}

	handler := httpapi.NewHandler(mint.NewService(keyStore), keyStore, internalToken)

	addr := os.Getenv("AXTO_ADDR")
	if addr == "" {
		addr = ":8090"
	}

	log.Printf("axto listening on %s", addr)
	if err := http.ListenAndServe(addr, handler.Routes()); err != nil {
		log.Fatal(err)
	}
}
