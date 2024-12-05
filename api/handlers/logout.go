package handlers

import (
	"context"

	"github.com/eidng8/go-attr-rbac/api"
)

func (s Server) Logout(
	ctx context.Context, _ LogoutRequestObject,
) (LogoutResponseObject, error) {
	err := s.revokeAccessToken(ctx)
	if err != nil {
		api.Log.Debugf("failed to revoke access token: %v", err)
		return Logout401JSONResponse{}, err
	}
	return Logout204Response{}, nil
}
