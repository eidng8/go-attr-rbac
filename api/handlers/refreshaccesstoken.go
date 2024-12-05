package handlers

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/api"
)

func (s Server) RefreshAccessToken(
	ctx context.Context, _ RefreshAccessTokenRequestObject,
) (RefreshAccessTokenResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	token, err := s.getRefreshToken(gc)
	if err != nil {
		return RefreshAccessToken401JSONResponse{}, nil
	}
	at, err := s.issueAccessToken(token.user)
	if err != nil {
		api.Log.Debugf("failed to issue access token: %v", err)
		return RefreshAccessToken401JSONResponse{}, nil
	}
	rt, err := s.issueRefreshToken(token.user)
	if err != nil {
		api.Log.Debugf("failed to issue refresh token: %v", err)
		return RefreshAccessToken401JSONResponse{}, nil
	}
	s.setToken(gc, at, rt)
	return RefreshAccessToken204Response{}, nil
}
