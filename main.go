package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/mr-tron/base58"
)

type PrivateKey []byte

type PublicKey [32]byte

func NewRandomPrivateKey() (PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var publicKey PublicKey
	copy(publicKey[:], pub)
	return PrivateKey(priv), nil
}

func (k PrivateKey) PublicKey() PublicKey {
	p := ed25519.PrivateKey(k)
	pub := p.Public().(ed25519.PublicKey)

	var publicKey PublicKey
	copy(publicKey[:], pub)

	return publicKey
}

func main() {
	// Generate a random private key
	privateKey, err := NewRandomPrivateKey()
	if err != nil {
		fmt.Println("Error generating random private key:", err)
		return
	}

	// Print the private key in Base58
	fmt.Println("Generated private key (Base58):", base58.Encode(privateKey))

	// Get the corresponding public key
	publicKey := privateKey.PublicKey()

	// Print the public key in Base58
	fmt.Println("Corresponding public key (Base58):", base58.Encode(publicKey[:]))
}

