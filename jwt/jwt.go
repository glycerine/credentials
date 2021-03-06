package jwt

import (
	"crypto/rsa"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/jws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

var (
	ErrVerification          = grpc.Errorf(codes.Unauthenticated, "credentials: verification error")
	ErrDecoding              = grpc.Errorf(codes.Unauthenticated, "credentials: decoding error")
	ErrCredentialsMissing    = grpc.Errorf(codes.Unauthenticated, "credentials: missing credentials")
	ErrAuthorizationRequired = grpc.Errorf(codes.Unauthenticated, "credentials: authorization required")
	ErrTokenTypeInvalid      = grpc.Errorf(codes.Unauthenticated, "credentials: token type invalid")
)

type Options struct {
	Key       *rsa.PublicKey
	TokenType string
}

type Credentials struct {
	Options Options
}

func NewCredentials(options Options) *Credentials {
	if options.TokenType == "" {
		options.TokenType = "Bearer"
	}

	return &Credentials{options}
}

func (c Credentials) FromString(token string) (*jws.ClaimSet, error) {
	if c.Options.Key != nil {
		err := jws.Verify(token, c.Options.Key)
		if err != nil {
			return nil, ErrVerification
		}
	}

	claims, err := jws.Decode(token)
	if err != nil {
		return nil, ErrDecoding
	}

	return claims, err
}

func (c Credentials) FromContext(ctx context.Context) (*jws.ClaimSet, error) {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return nil, ErrCredentialsMissing
	}

	raw, ok := md["authorization"]
	if !ok {
		return nil, ErrAuthorizationRequired
	}

	value := raw[0]

	parts := strings.Split(value, " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != strings.ToLower(c.Options.TokenType) {
		return nil, ErrTokenTypeInvalid
	}

	return c.FromString(parts[1])
}

func (c Credentials) UnaryServerInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	claims, err := c.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, "claims", claims)

	return handler(ctx, req)
}
