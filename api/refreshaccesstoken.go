package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s Server) RefreshAccessToken(
	ctx context.Context, _ RefreshAccessTokenRequestObject,
) (RefreshAccessTokenResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, ErrInvalidContext
	}
	token, err := s.getRefreshToken(gc)
	if err != nil {
		return RefreshAccessToken401Response{}, nil
	}
	at, err := s.issueAccessToken(token.user)
	if err != nil {
		log.Debugf("failed to issue access token: %v", err)
		return RefreshAccessToken401Response{}, nil
	}
	rt, err := s.issueRefreshToken(token.user)
	if err != nil {
		log.Debugf("failed to issue refresh token: %v", err)
		return RefreshAccessToken401Response{}, nil
	}
	gc.SetSameSite(http.SameSiteStrictMode)
	s.setCookie(gc, AccessTokenName, at, "/", 3600)
	s.setCookie(gc, RefreshTokenName, rt, "/access-token", 7*24*3600)
	return RefreshAccessToken204Response{}, nil
}
