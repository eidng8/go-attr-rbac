package main

// KeyManager is an interface for managing keys.
type KeyManager interface {
	// GetPrivateKey returns the private key used to generate JWT tokens.
	GetPrivateKey() string
}
