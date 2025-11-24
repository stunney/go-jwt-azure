package azure

import (
	"crypto"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/golang-jwt/jwt/v5"
)

// HashAlgorithms maps JWK signing algorithms to their corresponding hash algorithms.
var HashAlgorithms = map[azkeys.SignatureAlgorithm]crypto.Hash{
	azkeys.SignatureAlgorithmES256:  crypto.SHA256,
	azkeys.SignatureAlgorithmES256K: crypto.SHA256,
	azkeys.SignatureAlgorithmES384:  crypto.SHA384,
	azkeys.SignatureAlgorithmES512:  crypto.SHA512,
	azkeys.SignatureAlgorithmPS256:  crypto.SHA256,
	azkeys.SignatureAlgorithmPS384:  crypto.SHA384,
	azkeys.SignatureAlgorithmPS512:  crypto.SHA512,
	azkeys.SignatureAlgorithmRS256:  crypto.SHA256,
	azkeys.SignatureAlgorithmRS384:  crypto.SHA384,
	azkeys.SignatureAlgorithmRS512:  crypto.SHA512,
}

// ComputeHash computes the digest of the message with the given hash algorithm.
func ComputeHash(algorithm azkeys.SignatureAlgorithm, message []byte) ([]byte, error) {
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
