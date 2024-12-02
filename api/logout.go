package api

import (
	"context"
)

func (s Server) Logout(
	ctx context.Context, _ LogoutRequestObject,
) (LogoutResponseObject, error) {
	err := s.revokeAccessToken(ctx)
	if err != nil {
		log.Debugf("failed to revoke access token: %v", err)
		return Logout401Response{}, err
	}
	return Logout204Response{}, nil
}
