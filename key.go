package azure

import (
	"context"
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
}

// NewKey create a remote key referenced by a key identifier.
func NewKey(client azkeys.Client, keyID string) (*Key, error) {
	return NewKeyWithContext(context.Background(), client, keyID)
}

// NewKeyWithContext create a remote key referenced by a key identifier with context.
func NewKeyWithContext(ctx context.Context, client azkeys.Client, keyID string) (*Key, error) {
	keyURL, err := url.Parse(keyID)
	if err != nil {
		return nil, jwt.ErrInvalidKey
	}

	parts := strings.Split(strings.TrimPrefix(keyURL.Path, "//"), "/")
	if len(parts) != 3 {
		return nil, jwt.ErrInvalidKey
	}
	if parts[0] != "keys" {
		return nil, jwt.ErrInvalidKey
	}

	return &Key{
		Client:       &client,
		Context:      ctx,
		id:           keyID,
		vaultBaseURL: keyURL.Scheme + "://" + keyURL.Host,
		name:         parts[1],
		version:      parts[2],
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
