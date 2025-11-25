package azure

/*
Copyright 2025 Stephen Tunney

SETUP:  In order for these tests to run, you must have an Azure Key Vault and the running user/SP must have appropriate permissions.
"Key Vault Secrets Officer" is heavy handed but will do the trick for testing as long as the permissions are scoped to just the test vault.

*/

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/golang-jwt/jwt/v5"

	"github.com/joho/godotenv"
)

var (
	keysClient *azkeys.Client
	// secretsClient *azsecrets.Client
	// certsClient   *azcertificates.Client
	keyVaultURL string
	rsaKeyName  string
	ecKeyName   string
	certName    string
)

func test_init() {
	if keysClient != nil {
		// Already configured
		return
	}

	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	keyVaultURL = os.Getenv("AZURE_KEYVAULT_URL")
	rsaKeyName = os.Getenv("AZURE_KEY_NAME_RSA")
	ecKeyName = os.Getenv("AZURE_KEY_NAME_EC")
	certName = os.Getenv("AZURE_CERT_NAME")

	if keyVaultURL == "" || rsaKeyName == "" || ecKeyName == "" || certName == "" {
		fmt.Println("Skipping functional tests: AZURE_KEYVAULT_URL, AZURE_KEY_NAME_RSA, AZURE_KEY_NAME_EC, or AZURE_CERT_NAME environment variables not set.")
		os.Exit(0)
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		fmt.Printf("Failed to create credential: %v\n", err)
		os.Exit(1)
	}

	keysClient, err = azkeys.NewClient(keyVaultURL, cred, nil)
	if err != nil {
		fmt.Printf("Failed to create azkeys client: %v\n", err)
		os.Exit(1)
	}

	// secretsClient, err = azsecrets.NewClient(keyVaultURL, cred, nil)
	// if err != nil {
	// 	fmt.Printf("Failed to create azsecrets client: %v\n", err)
	// 	os.Exit(1)
	// }

	// certsClient, err = azcertificates.NewClient(keyVaultURL, cred, nil)
	// if err != nil {
	// 	fmt.Printf("Failed to create azcertificates client: %v\n", err)
	// 	os.Exit(1)
	// }
}

func getKeyVersion(t *testing.T, keyName string) string {
	t.Helper()

	props := azkeys.ListKeyPropertiesVersionsOptions{}

	pager := keysClient.NewListKeyPropertiesVersionsPager(keyName, &props)
	if pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			t.Fatalf("Failed to list key versions for %s: %v", keyName, err)
		}
		if len(page.Value) > 0 {
			// Get the latest version
			return page.Value[0].KID.Version()
		}
	}
	t.Fatalf("No versions found for key %s", keyName)
	return ""
}

func TestNewKey(t *testing.T) {
	test_init()

	keyName := fmt.Sprintf("%s-%s", rsaKeyName, uuid.New().String())

	createParams := azkeys.CreateKeyParameters{
		Kty: to.Ptr(azkeys.KeyTypeRSA),
		KeyAttributes: &azkeys.KeyAttributes{
			//Exportable: to.Ptr(true),
			Enabled: to.Ptr(true),
		},
		KeySize: to.Ptr(int32(2048)), // Key size in bits
		KeyOps: []*azkeys.KeyOperation{
			to.Ptr(azkeys.KeyOperationEncrypt),
			to.Ptr(azkeys.KeyOperationDecrypt),
			to.Ptr(azkeys.KeyOperationSign),
			to.Ptr(azkeys.KeyOperationVerify),
		},
	}

	response, err := keysClient.CreateKey(context.Background(), keyName, createParams, nil)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	defer func() {
		_, err := keysClient.DeleteKey(context.Background(), keyName, nil)
		if err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}
	}()

	rsaKeyVersion := getKeyVersion(t, response.Key.KID.Name())
	keyID := fmt.Sprintf("%s/keys/%s/%s", keyVaultURL, keyName, rsaKeyVersion)

	t.Run("ValidKeyID", func(t *testing.T) {
		key, err := NewKey(*keysClient, keyID)
		if err != nil {
			t.Fatalf("NewKey() with valid ID failed: %v", err)
		}
		if key == nil {
			t.Fatal("NewKey() returned a nil key for a valid ID")
		}
		if key.name != keyName {
			t.Errorf("Expected key name %s, got %s", keyName, key.name)
		}
		if key.version != rsaKeyVersion {
			t.Errorf("Expected key version %s, got %s", rsaKeyVersion, key.version)
		}
	})

	t.Run("InvalidKeyID", func(t *testing.T) {
		invalidIDs := []string{
			"not-a-url",
			"http://foo/bar",
			"http://foo/secrets/bar/baz",
		}

		for _, id := range invalidIDs {
			_, err := NewKey(*keysClient, id)
			if err != jwt.ErrInvalidKey {
				t.Errorf("Expected ErrInvalidKey for id '%s', got %v", id, err)
			}
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	test_init()

	testCases := []struct {
		name      string
		keyName   string
		algorithm azkeys.SignatureAlgorithm
	}{
		{"RSA-RS256", rsaKeyName, azkeys.SignatureAlgorithmRS256},
		{"RSA-RS384", rsaKeyName, azkeys.SignatureAlgorithmRS384},
		{"RSA-RS512", rsaKeyName, azkeys.SignatureAlgorithmRS512},
		{"EC-ES256", ecKeyName, azkeys.SignatureAlgorithmES256},
		{"EC-ES384", ecKeyName, azkeys.SignatureAlgorithmES384},
		{"EC-ES512", ecKeyName, azkeys.SignatureAlgorithmES512},
	}

	message := []byte("This is a test message for signing.")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testCreateKeyAndSignAndVerifyWithIt(t, tc.name, tc.keyName, tc.algorithm, message)
		})
	}
}

func testCreateKeyAndSignAndVerifyWithIt(t *testing.T, name, keyname_base string, algorithm azkeys.SignatureAlgorithm, message []byte) {
	keyType := strings.Split(name, "-")[0]

	keyname := fmt.Sprintf("%s-%s", keyname_base, uuid.New().String())

	createParams := azkeys.CreateKeyParameters{
		Kty: to.Ptr(azkeys.KeyType(keyType)), // "RSA" or "EC"
		KeyAttributes: &azkeys.KeyAttributes{
			//Exportable: to.Ptr(true),
			Enabled: to.Ptr(true),
		},
		KeyOps: []*azkeys.KeyOperation{
			to.Ptr(azkeys.KeyOperationSign),
			to.Ptr(azkeys.KeyOperationVerify),
		},
	}

	switch keyType {
	case "RSA":
		createParams.KeySize = to.Ptr(int32(2048)) // Key size in bits
	case "EC":
		switch algorithm {
		case azkeys.SignatureAlgorithmES256:
			createParams.Curve = to.Ptr(azkeys.CurveNameP256)
		case azkeys.SignatureAlgorithmES384:
			createParams.Curve = to.Ptr(azkeys.CurveNameP384)
		case azkeys.SignatureAlgorithmES512:
			createParams.Curve = to.Ptr(azkeys.CurveNameP521)
		}
	}

	response, err := keysClient.CreateKey(context.Background(), keyname, createParams, nil)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	defer func() {
		_, err := keysClient.DeleteKey(context.Background(), keyname, nil)
		if err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}
	}()

	//keyVersion := getKeyVersion(t, response.Key.KID.Name())
	keyID := fmt.Sprintf("%s/keys/%s/%s", keyVaultURL, response.Key.KID.Name(), "")
	key, err := NewKey(*keysClient, keyID)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Test Sign and Verify
	signature, err := key.Sign(algorithm, message)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) == 0 {
		t.Fatal("Sign() returned an empty signature")
	}

	err = key.Verify(algorithm, message, signature)
	if err != nil {
		t.Errorf("Verify() failed: %v", err)
	}

	// Test with invalid signature
	tamperedSignature := append([]byte{0}, signature...)
	err = key.Verify(algorithm, message, tamperedSignature)
	if err == nil {
		t.Error("Verify() should fail with a tampered signature")
	}
}

func TestSigningJWT(t *testing.T) {
	test_init()

	keyname_base := "jwtkey"
	keyType := "EC"
	algorithm := azkeys.SignatureAlgorithmES512

	keyname := fmt.Sprintf("%s-%s", keyname_base, uuid.New().String())

	createParams := azkeys.CreateKeyParameters{
		Kty: to.Ptr(azkeys.KeyType(keyType)), // "RSA" or "EC"
		KeyAttributes: &azkeys.KeyAttributes{
			//Exportable: to.Ptr(true),
			Enabled: to.Ptr(true),
		},
		KeyOps: []*azkeys.KeyOperation{
			to.Ptr(azkeys.KeyOperationSign),
			to.Ptr(azkeys.KeyOperationVerify),
		},
	}

	switch keyType {
	case "RSA":
		createParams.KeySize = to.Ptr(int32(2048)) // Key size in bits
	case "EC":
		switch algorithm {
		case azkeys.SignatureAlgorithmES256:
			createParams.Curve = to.Ptr(azkeys.CurveNameP256)
		case azkeys.SignatureAlgorithmES384:
			createParams.Curve = to.Ptr(azkeys.CurveNameP384)
		case azkeys.SignatureAlgorithmES512:
			createParams.Curve = to.Ptr(azkeys.CurveNameP521)
		}
	}

	response, err := keysClient.CreateKey(context.Background(), keyname, createParams, nil)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	defer func() {
		_, err := keysClient.DeleteKey(context.Background(), keyname, nil)
		if err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}
	}()

	//keyVersion := getKeyVersion(t, response.Key.KID.Name())
	keyID := fmt.Sprintf("%s/keys/%s/%s", keyVaultURL, response.Key.KID.Name(), "")
	key, err := NewKey(*keysClient, keyID)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	m := SigningMethods[algorithm] //Ensure the method is registered
	// Create and sign a JWT - JUST LIKE NORMAL!
	token := jwt.NewWithClaims(m, jwt.MapClaims{
		"iss": "your-issuer",
		"sub": "user@example.com",
		"aud": "your-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Sign with Azure Key Vault - same API as always!
	tokenString, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}

	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm
		if _, ok := token.Method.(*SigningMethod); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the public key for verification
		pub, err := key.PublicKey()
		if err != nil {
			return nil, err
		}
		return pub, nil
	})

	if err != nil {
		panic(err)
	}

	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		fmt.Println("Token is valid!")
		fmt.Printf("Subject: %v\n", claims["sub"])
	}

}

// func TestCertificate(t *testing.T) {
// 	test_init()

// 	policy := azcertificates.CreateCertificateParameters{
// 		CertificateAttributes: &azcertificates.CertificateAttributes{
// 			Enabled: to.Ptr(true),
// 		},
// 		CertificatePolicy: &azcertificates.CertificatePolicy{
// 			IssuerParameters: &azcertificates.IssuerParameters{
// 				Name: to.Ptr("Self"),
// 			},
// 			KeyProperties: &azcertificates.KeyProperties{
// 				Exportable: to.Ptr(true),
// 				KeyType:    to.Ptr(azcertificates.KeyTypeRSA),
// 				KeySize:    to.Ptr[int32](2048),
// 				ReuseKey:   to.Ptr(true),
// 			},
// 			SecretProperties: &azcertificates.SecretProperties{
// 				ContentType: to.Ptr("application/x-pkcs12"),
// 			},
// 			X509CertificateProperties: &azcertificates.X509CertificateProperties{
// 				ValidityInMonths: to.Ptr[int32](1),
// 				Subject:          to.Ptr("CN=testcert"),
// 				SubjectAlternativeNames: &azcertificates.SubjectAlternativeNames{
// 					DNSNames: []*string{
// 						to.Ptr("test.example.com"),
// 					},
// 				},
// 				KeyUsage: []*azcertificates.KeyUsageType{
// 					to.Ptr(azcertificates.KeyUsageTypeCRLSign),
// 				},
// 			},

// 			// KeyOperations: []*azcertificates.KeyOperation{
// 			// 	to.Ptr(azcertificates.KeyOperationSign),
// 			// 	to.Ptr(azcertificates.KeyOperationVerify),
// 			// },
// 		},
// 	}

// 	opts := azcertificates.CreateCertificateOptions{}

// 	resp, err := certsClient.CreateCertificate(t.Context(), certName, policy, &opts)
// 	if err != nil {
// 		t.Fatalf("CreateCertificate failed: %v", err)
// 	}

// 	if resp.Error.Code != "" {
// 		//Dead check
// 		t.Fatalf("CreateCertificate returned error code: %s, message: %s", resp.Error.Code, resp.Error.Code)
// 	}

// 	defer func() {
// 		_, err := certsClient.DeleteCertificate(context.Background(), certName, nil)
// 		if err != nil {
// 			t.Fatalf("Failed to delete key: %v", err)
// 		}
// 	}()

// 	certVersion := getKeyVersion(t, certName)
// 	keyID := fmt.Sprintf("%s/keys/%s/%s", keyVaultURL, certName, certVersion)

// 	key, err := NewKey(*keysClient, *secretsClient, keyID)
// 	if err != nil {
// 		t.Fatalf("Failed to create key for certificate: %v", err)
// 	}

// 	cert, err := key.Certificate()
// 	if err != nil {
// 		t.Fatalf("Certificate() failed: %v", err)
// 	}

// 	if cert == nil {
// 		t.Fatal("Certificate() returned a nil certificate")
// 	}

// 	// Verify the public key from the certificate can verify a signature from the key vault key
// 	message := []byte("test message")
// 	digest := sha256.Sum256(message)

// 	signature, err := key.Sign(azkeys.SignatureAlgorithmRS256, digest[:])
// 	if err != nil {
// 		t.Fatalf("SignDigest for certificate test failed: %v", err)
// 	}

// 	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
// 	if !ok {
// 		// If not RSA, try EC
// 		ecPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
// 		if !ok {
// 			t.Fatalf("Certificate public key is not RSA or ECDSA")
// 		}
// 		if !ecdsa.VerifyASN1(ecPubKey, digest[:], signature) {
// 			t.Error("ECDSA signature verification with certificate public key failed")
// 		}
// 		return
// 	}

// 	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest[:], signature)
// 	if err != nil {
// 		t.Errorf("RSA signature verification with certificate public key failed: %v", err)
// 	}
// }
