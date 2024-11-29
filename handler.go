package main

import (
	"io"

	"github.com/eidng8/go-attr-rbac/ent/schema"
)

type Handler interface {
	// GetUser retrieves the user designated by `credentials`. Returns `nil` if
	// the `credentials` are invalid or any error occurred.
	GetUser(credentials io.Reader) (*schema.User, error)
}
