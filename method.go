package azure

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/golang-jwt/jwt/v5"
)

// Specific instances of SigningMethod for a certain algorithms.
var (
	SigningMethodES256  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmES256}
	SigningMethodES256K = &SigningMethod{algorithm: azkeys.SignatureAlgorithmES256K}
	SigningMethodES384  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmES384}
	SigningMethodES512  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmES512}
	SigningMethodPS256  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmPS256}
	SigningMethodPS384  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmPS384}
	SigningMethodPS512  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmPS512}
	SigningMethodRS256  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmRS256}
	SigningMethodRS384  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmRS384}
	SigningMethodRS512  = &SigningMethod{algorithm: azkeys.SignatureAlgorithmRS512}
)

// SigningMethods maps JWK signing algorithms to their corresponding implementation.
var SigningMethods = map[azkeys.SignatureAlgorithm]*SigningMethod{
	azkeys.SignatureAlgorithmES256:  SigningMethodES256,
	azkeys.SignatureAlgorithmES256K: SigningMethodES256K,
	azkeys.SignatureAlgorithmES384:  SigningMethodES384,
	azkeys.SignatureAlgorithmES512:  SigningMethodES512,
	azkeys.SignatureAlgorithmPS256:  SigningMethodPS256,
	azkeys.SignatureAlgorithmPS384:  SigningMethodPS384,
	azkeys.SignatureAlgorithmPS512:  SigningMethodPS512,
	azkeys.SignatureAlgorithmRS256:  SigningMethodRS256,
	azkeys.SignatureAlgorithmRS384:  SigningMethodRS384,
	azkeys.SignatureAlgorithmRS512:  SigningMethodRS512,
}

// SigningMethod for Azure Key Vault.
type SigningMethod struct {
	algorithm azkeys.SignatureAlgorithm
}

func init_signing_methods() {
	for _, method := range SigningMethods {
		jwt.RegisterSigningMethod(method.Alg(), func() jwt.SigningMethod {
			return method
		})
	}
}

// Alg identifies the signing / verification algorithm.
// For more information on possible algorithm types,
// see https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm
func (m *SigningMethod) Alg() string {
	return string(m.algorithm)
}

// Sign signs the signing string remotely.
func (m *SigningMethod) Sign(signingString string, key any) ([]byte, error) {
	// Check the key
	k, ok := key.(*Key)
	if !ok {
		return nil, jwt.ErrInvalidKeyType
	}

	// Sign the string
	sig, err := k.Sign(m.algorithm, []byte(signingString))
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify verifies the singing string against the signature remotely.
func (m *SigningMethod) Verify(signingString string, signature []byte, key any) error {
	// Check the key
	k, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	var hasher crypto.Hash
	switch m.algorithm {
	case "ES256":
		hasher = crypto.SHA256
	case "ES384":
		hasher = crypto.SHA384
	case "ES512":
		hasher = crypto.SHA512
	default:
		return errors.New("unsupported algorithm")
	}

	h := hasher.New()
	h.Write([]byte(signingString))
	digest := h.Sum(nil)

	// Parse signature (IEEE P1363 format: r || s)
	keyBytes := (k.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keyBytes {
		return errors.New("invalid signature length")
	}

	r := big.NewInt(0).SetBytes(signature[:keyBytes])
	s := big.NewInt(0).SetBytes(signature[keyBytes:])

	// Verify signature
	if !ecdsa.Verify(k, digest, r, s) {
		return errors.New("signature verification failed")
	}

	return nil
}
