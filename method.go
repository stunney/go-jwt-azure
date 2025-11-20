package azure

import (
	"encoding/base64"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/golang-jwt/jwt/v5"
)

// Specific instances of SigningMethod for a certain algorithms.
var (
	SigningMethodES256  = &SigningMethod{algorithm: keyvault.ES256}
	SigningMethodES256K = &SigningMethod{algorithm: keyvault.ES256K}
	SigningMethodES384  = &SigningMethod{algorithm: keyvault.ES384}
	SigningMethodES512  = &SigningMethod{algorithm: keyvault.ES512}
	SigningMethodPS256  = &SigningMethod{algorithm: keyvault.PS256}
	SigningMethodPS384  = &SigningMethod{algorithm: keyvault.PS384}
	SigningMethodPS512  = &SigningMethod{algorithm: keyvault.PS512}
	SigningMethodRS256  = &SigningMethod{algorithm: keyvault.RS256}
	SigningMethodRS384  = &SigningMethod{algorithm: keyvault.RS384}
	SigningMethodRS512  = &SigningMethod{algorithm: keyvault.RS512}
)

// SigningMethods maps JWK signing algorithms to their corresponding implementation.
var SigningMethods = map[keyvault.JSONWebKeySignatureAlgorithm]*SigningMethod{
	keyvault.ES256:  SigningMethodES256,
	keyvault.ES256K: SigningMethodES256K,
	keyvault.ES384:  SigningMethodES384,
	keyvault.ES512:  SigningMethodES512,
	keyvault.PS256:  SigningMethodPS256,
	keyvault.PS384:  SigningMethodPS384,
	keyvault.PS512:  SigningMethodPS512,
	keyvault.RS256:  SigningMethodRS256,
	keyvault.RS384:  SigningMethodRS384,
	keyvault.RS512:  SigningMethodRS512,
}

// SigningMethod for Azure Key Vault.
type SigningMethod struct {
	algorithm keyvault.JSONWebKeySignatureAlgorithm
}

// Alg identifies the signing / verification algorithm.
// For more information on possible algorithm types,
// see https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm
func (m *SigningMethod) Alg() string {
	return string(m.algorithm)
}

// Sign signs the signing string remotely.
func (m *SigningMethod) Sign(signingString string, key interface{}) (string, error) {
	// Check the key
	k, ok := key.(*Key)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	// Sign the string
	sig, err := k.Sign(m.algorithm, []byte(signingString))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify verifies the singing string against the signature remotely.
func (m *SigningMethod) Verify(signingString, signature string, key interface{}) error {
	// Check the key
	k, ok := key.(*Key)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	// Verify the string
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	return k.Verify(m.algorithm, []byte(signingString), sig)
}
