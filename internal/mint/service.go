// Package mint implements Axto's one real capability: sign a claim set as
// a token. It never decides what belongs in the claims -- that's the
// caller's job entirely (see the design doc's "Axto's contract never
// changes" principle). This package has no database and no opinion about
// organizations, applications, or service accounts.
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
}

func NewService(keyStore keys.Store) *Service {
	return &Service{keys: keyStore}
}

func (s *Service) Mint(ctx context.Context, req Request) (*Result, error) {
	if req.TokenType != "jwt" {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTokenType, req.TokenType)
	}
	if req.TTL <= 0 {
		return nil, fmt.Errorf("mint: ttl must be positive")
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
