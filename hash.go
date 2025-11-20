package azure

import (
	"crypto"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/golang-jwt/jwt/v5"
)

// HashAlgorithms maps JWK signing algorithms to their corresponding hash algorithms.
var HashAlgorithms = map[keyvault.JSONWebKeySignatureAlgorithm]crypto.Hash{
	keyvault.ES256:  crypto.SHA256,
	keyvault.ES256K: crypto.SHA256,
	keyvault.ES384:  crypto.SHA384,
	keyvault.ES512:  crypto.SHA512,
	keyvault.PS256:  crypto.SHA256,
	keyvault.PS384:  crypto.SHA384,
	keyvault.PS512:  crypto.SHA512,
	keyvault.RS256:  crypto.SHA256,
	keyvault.RS384:  crypto.SHA384,
	keyvault.RS512:  crypto.SHA512,
}

// ComputeHash computes the digest of the message with the given hash algorithm.
func ComputeHash(algorithm keyvault.JSONWebKeySignatureAlgorithm, message []byte) ([]byte, error) {
	hash, ok := HashAlgorithms[algorithm]
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}
	if !hash.Available() {
		return nil, jwt.ErrHashUnavailable
	}
	h := hash.New()
	if _, err := h.Write(message); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
