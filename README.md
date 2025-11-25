# go-jwt-azure
jwt-go signing methods backed by Azure Key Vault

## Example

```go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	jwtazure "github.com/stunney/go-jwt-azure"
)

func main() {
	// Extract parameters
	keyVaultURL = os.Getenv("AZURE_KEYVAULT_URL")

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

	// If you require a specific version and not just the latest, use this
	//keyID := fmt.Sprintf("%s/keys/%s/%s", keyVaultURL, keyName, keyVersion)

	keyID := fmt.Sprintf("%s/keys/%s/%s", keyVaultURL, keyName)

	key, err := NewKey(*keysClient, keyID)
	if err != nil {
		fail(err)
	}

	algo := jwtazure.SigningMethodES512

	// Generate a JWT token
	token := jwt.NewWithClaims(algo, jwt.MapClaims{
		"sub": "demo",
	})
	serialized, err := token.SignedString(key)
	fail(err)

	// Print the serialized token
	fmt.Println(serialized)

	// Parse and verify the token locally

	err = key.Verify(algo, message, signature)
	if err != nil {
		t.Errorf("Verify() failed: %v", err)
	}

	fail(err)
}

func fail(err error) {
	if err != nil {
		panic(err)
	}
}

```