package api

import (
	"context"
)

// RevokeAccessToken revokes the current access token and its corresponding refresh token.
//
// Endpoint: DELETE /access-token
func (s Server) RevokeAccessToken(
	ctx context.Context, _ RevokeAccessTokenRequestObject,
) (RevokeAccessTokenResponseObject, error) {
	err := s.revokeAccessToken(ctx)
	if err != nil {
		Log.Debugf("failed to revoke access token: %v", err)
		return RevokeAccessToken401JSONResponse{}, nil
	}
	return RevokeAccessToken204Response{}, nil
}
