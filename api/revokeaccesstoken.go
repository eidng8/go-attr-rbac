package api

import "context"

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
