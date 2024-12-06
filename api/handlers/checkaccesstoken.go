package handlers

import (
	"context"
)

// CheckAccessToken checks whether current access token is valid.
//
// Endpoint: GET /access-token
func (s Server) CheckAccessToken(
	ctx context.Context, _ CheckAccessTokenRequestObject,
) (CheckAccessTokenResponseObject, error) {
	return CheckAccessToken204Response{}, nil
}
