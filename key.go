package azure

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault/keyvaultapi"
	"github.com/golang-jwt/jwt/v5"
)

// Key represents a remote key in the Azure Key Vault.
type Key struct {
	Client  keyvaultapi.BaseClientAPI
	Context context.Context

	id           string
	vaultBaseURL string
	name         string
	version      string
}

// NewKey create a remote key referenced by a key identifier.
func NewKey(client keyvaultapi.BaseClientAPI, keyID string) (*Key, error) {
	return NewKeyWithContext(context.Background(), client, keyID)
}

// NewKeyWithContext create a remote key referenced by a key identifier with context.
func NewKeyWithContext(ctx context.Context, client keyvaultapi.BaseClientAPI, keyID string) (*Key, error) {
	keyURL, err := url.Parse(keyID)
	if err != nil {
		return nil, jwt.ErrInvalidKey
	}

	parts := strings.Split(strings.TrimPrefix(keyURL.Path, "/"), "/")
	if len(parts) != 3 {
		return nil, jwt.ErrInvalidKey
	}
	if parts[0] != "keys" {
		return nil, jwt.ErrInvalidKey
	}

	return &Key{
		Client:       client,
		Context:      ctx,
		id:           keyID,
		vaultBaseURL: keyURL.Scheme + "://" + keyURL.Host,
		name:         parts[1],
		version:      parts[2],
	}, nil
}

// Sign signs the message with the algorithm provided.
func (k *Key) Sign(algorithm keyvault.JSONWebKeySignatureAlgorithm, message []byte) ([]byte, error) {
	digest, err := ComputeHash(algorithm, message)
	if err != nil {
		return nil, err
	}
	return k.SignDigest(algorithm, digest)
}

// SignDigest signs the message digest with the algorithm provided.
func (k *Key) SignDigest(algorithm keyvault.JSONWebKeySignatureAlgorithm, digest []byte) ([]byte, error) {
	// Prepare the message
	value := base64.RawURLEncoding.EncodeToString(digest)

	// Sign the message
	res, err := k.Client.Sign(
		k.Context,
		k.vaultBaseURL,
		k.name,
		k.version,
		keyvault.KeySignParameters{
			Algorithm: algorithm,
			Value:     &value,
		},
	)
	if err != nil {
		return nil, err
	}

	// Verify the result
	if res.Kid == nil || *res.Kid != k.id {
		return nil, ErrMismatchResponseKeyID
	}
	if res.Result == nil {
		return nil, ErrInvalidServerResponse
	}
	return base64.RawURLEncoding.DecodeString(*res.Result)
}

// Verify verifies the message  with the algorithm provided against the signature.
func (k *Key) Verify(algorithm keyvault.JSONWebKeySignatureAlgorithm, message, signature []byte) error {
	digest, err := ComputeHash(algorithm, message)
	if err != nil {
		return err
	}
	return k.VerifyDigest(algorithm, digest, signature)
}

// VerifyDigest verifies the message digest with the algorithm provided against the signature.
func (k *Key) VerifyDigest(algorithm keyvault.JSONWebKeySignatureAlgorithm, digest, signature []byte) error {
	// Prepare for verification
	encodedDigest := base64.RawURLEncoding.EncodeToString(digest)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Verify the message digest
	res, err := k.Client.Verify(
		k.Context,
		k.vaultBaseURL,
		k.name,
		k.version,
		keyvault.KeyVerifyParameters{
			Algorithm: algorithm,
			Digest:    &encodedDigest,
			Signature: &encodedSignature,
		},
	)
	if err != nil {
		return err
	}
	if res.Value == nil {
		return ErrInvalidServerResponse
	}
	if valid := *res.Value; !valid {
		return ErrVerification
	}
	return nil
}

// Certificate returns the X.509 certificate associated with the key.
func (k *Key) Certificate() (*x509.Certificate, error) {
	res, err := k.Client.GetCertificate(
		k.Context,
		k.vaultBaseURL,
		k.name,
		k.version,
	)
	if err != nil {
		return nil, err
	}
	if res.Cer == nil {
		return nil, ErrInvalidServerResponse
	}
	return x509.ParseCertificate(*res.Cer)
}
