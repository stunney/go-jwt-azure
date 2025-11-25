package azure

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/golang-jwt/jwt/v5"
)

// Key represents a remote key in the Azure Key Vault.
type Key struct {
	//Client  keyvaultapi.BaseClientAPI

	Client *azkeys.Client

	Context context.Context

	id           string
	vaultBaseURL string
	name         string
	version      string
	publicKey    *ecdsa.PublicKey
}

// NewKey create a remote key referenced by a key identifier.
func NewKey(client azkeys.Client, keyID string) (*Key, error) {
	return NewKeyWithContext(context.Background(), client, keyID)
}

// NewKeyWithContext create a remote key referenced by a key identifier with context.
func NewKeyWithContext(ctx context.Context, client azkeys.Client, keyID string) (*Key, error) {
	init_signing_methods() //Register the signing methods

	keyURL, err := url.Parse(keyID)
	if err != nil {
		return nil, jwt.ErrInvalidKey
	}

	parts := strings.Split(strings.TrimPrefix(keyURL.Path, "//"), "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, jwt.ErrInvalidKey
	}
	if parts[0] != "keys" {
		return nil, jwt.ErrInvalidKey
	}

	version := ""

	if len(parts) == 3 {
		version = parts[2]
	}

	ret := &Key{
		Client:       &client,
		Context:      ctx,
		id:           keyID,
		vaultBaseURL: keyURL.Scheme + "://" + keyURL.Host,
		name:         parts[1],
		version:      version,
	}

	return ret, nil
}

func (k *Key) PublicKey() (*ecdsa.PublicKey, error) {
	if k.publicKey != nil {
		return k.publicKey, nil
	}

	ctx := context.Background()
	getResp, err := k.Client.GetKey(ctx, k.name, k.version, nil)
	if err != nil {
		return nil, err
	}

	pubKey, err := k.extractPublicKey(getResp.Key)
	if err != nil {
		return nil, err
	}

	k.publicKey = pubKey
	return k.publicKey, nil
}

func (k *Key) extractPublicKey(key *azkeys.JSONWebKey) (*ecdsa.PublicKey, error) {
	if key.Kty == nil || *key.Kty != azkeys.KeyTypeEC {
		return nil, errors.New("key is not an EC key")
	}

	var curve elliptic.Curve
	switch *key.Crv {
	case azkeys.CurveNameP256:
		curve = elliptic.P256()
	case azkeys.CurveNameP384:
		curve = elliptic.P384()
	case azkeys.CurveNameP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %v", *key.Crv)
	}

	x := new(big.Int).SetBytes(key.X)
	y := new(big.Int).SetBytes(key.Y)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// Sign signs the message with the algorithm provided.
func (k *Key) Sign(algorithm azkeys.SignatureAlgorithm, message []byte) ([]byte, error) {
	digest, err := ComputeHash(algorithm, message)
	if err != nil {
		return nil, err
	}

	params := azkeys.SignParameters{
		Algorithm: &algorithm,
		Value:     digest[:],
	}

	opts := azkeys.SignOptions{}

	resp, err := k.Client.Sign(k.Context, k.name, k.version, params, &opts)
	if err != nil {
		return nil, err
	}

	if resp.Result == nil {
		return nil, ErrInvalidServerResponse //nolint:staticcheck
	}

	return resp.Result, nil
}

// Verify verifies the message  with the algorithm provided against the signature.
func (k *Key) Verify(algorithm azkeys.SignatureAlgorithm, message, signature []byte) error {
	digest, err := ComputeHash(algorithm, message)
	if err != nil {
		return err
	}

	params := azkeys.VerifyParameters{
		Algorithm: &algorithm,
		Digest:    digest[:],
		Signature: signature,
	}

	opts := azkeys.VerifyOptions{}

	resp, err := k.Client.Verify(k.Context, k.name, k.version, params, &opts)
	if err != nil {
		return err
	}

	if !*resp.Value {
		return ErrVerification //nolint:staticcheck
	}

	return nil
}
