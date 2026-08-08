// Package mint implements Axto's one real capability: sign a claim set as
// a token. It never decides what belongs in the claims -- that's entirely
// the caller's job.
package mint

import (
	"context"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/aniket/axto/internal/keys"
)

// ErrUnsupportedTokenType is returned for any TokenType other than "jwt".
// This is the extension point for a future DPoP-bound token type: a new
// accepted value and a new code path here, no change to the Request shape.
var ErrUnsupportedTokenType = errors.New("mint: unsupported token type")

// ErrTTLExceedsMax is returned when a request's TTL is longer than the
// Service's configured MaxTTL.
var ErrTTLExceedsMax = errors.New("mint: ttl exceeds maximum allowed")

// Request is what a caller asks Axto to sign. Claims is whatever the
// caller has already decided is worth asserting -- Axto only adds the
// bookkeeping claims (iat, exp, jti) that make sense to compute here
// rather than have every caller compute themselves.
type Request struct {
	Claims    map[string]any
	TokenType string // only "jwt" is supported today
	TTL       time.Duration
}

type Result struct {
	Token     string
	JTI       string
	ExpiresAt time.Time
}

type Service struct {
	keys keys.Store
	// maxTTL caps every Request's TTL. Zero means no cap. This exists
	// because a token signed with a TTL longer than a signing key's
	// retirement grace period (see keys.ManagedStore) could outlive its
	// own verifiability -- callers running a horizontally scaled Axto
	// should set this to their configured key-retirement window.
	maxTTL time.Duration
}

func NewService(keyStore keys.Store, maxTTL time.Duration) *Service {
	return &Service{keys: keyStore, maxTTL: maxTTL}
}

func (s *Service) Mint(ctx context.Context, req Request) (*Result, error) {
	if req.TokenType != "jwt" {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTokenType, req.TokenType)
	}
	if req.TTL <= 0 {
		return nil, fmt.Errorf("mint: ttl must be positive")
	}
	if s.maxTTL > 0 && req.TTL > s.maxTTL {
		return nil, fmt.Errorf("%w: %s > %s", ErrTTLExceedsMax, req.TTL, s.maxTTL)
	}

	key := s.keys.Current()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.PrivateKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": key.ID},
	})
	if err != nil {
		return nil, fmt.Errorf("mint: create signer: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(req.TTL)
	jti := uuid.NewString()

	claims := make(map[string]any, len(req.Claims)+3)
	for k, v := range req.Claims {
		claims[k] = v
	}
	claims["iat"] = now.Unix()
	claims["exp"] = expiresAt.Unix()
	claims["jti"] = jti

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return nil, fmt.Errorf("mint: sign token: %w", err)
	}

	return &Result{Token: token, JTI: jti, ExpiresAt: expiresAt}, nil
}
