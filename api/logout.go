package api

import (
	"context"
)

// Logout revokes the current access token and its corresponding refresh token.
// and clears the access and refresh token cookie.
//
// Endpoint: POST /logout
func (s Server) Logout(
	ctx context.Context, _ LogoutRequestObject,
) (LogoutResponseObject, error) {
	err := s.revokeAccessToken(ctx)
	if err != nil {
		Log.Debugf("failed to logout: %v", err)
		return Logout401JSONResponse{}, err
	}
	return Logout204Response{}, nil
}
