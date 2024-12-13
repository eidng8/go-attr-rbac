package handlers

import (
	"errors"
	"regexp"

	jsoniter "github.com/json-iterator/go"
)

// global names
const (
	accessTokenName  = "access_token"
	refreshTokenName = "refresh_token"
)

// drop in replacement for encoding/json
var json = jsoniter.ConfigCompatibleWithStandardLibrary

// password validations
var (
	numChecker       = regexp.MustCompile(`[0-9]+`)
	uppercaseChecker = regexp.MustCompile(`[A-Z]+`)
	lowercaseChecker = regexp.MustCompile(`[a-z]+`)
	specialChecker   = regexp.MustCompile(`[#?!@$%^&*-_]+`)

	errPasswordToSimple = errors.New(
		"password must contain at least 8 characters, " +
			"including uppercase, lowercase, number, and special characters" +
			" (#?!@$%^&*-_)",
	)
)

// error messages
var (
	errAccessDenied    = errors.New("access_denied")
	errEmptyToken      = errors.New("empty_token")
	errInvalidArgument = errors.New("invalid_argument")
	errInvalidContext  = errors.New("invalid_context")
	errInvalidHeader   = errors.New("invalid_header")
	errInvalidToken    = errors.New("invalid_token")

	// Denotes that either part of an assignment request is
	// invalid (e.g. not found). For example, when assigning a non-existing
	// role to a user; or a role to non-existing user.
	msgInvalidAssignment interface{} = "invalid_assignment"
	msgEmptyRequest      interface{} = "empty_request"
	msgError                         = "error"
	msgExists            interface{} = "already_exists"
	msgNotFound          interface{} = "not_found"
)
