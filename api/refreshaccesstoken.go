package api

import (
    "context"
    "fmt"
    "net/http"

    "github.com/gin-gonic/gin"
)

func (s Server) RefreshAccessToken(
    ctx context.Context, _ RefreshAccessTokenRequestObject,
) (RefreshAccessTokenResponseObject, error) {
    gc, ok := ctx.(*gin.Context)
    if !ok {
        return nil, fmt.Errorf("invalid context type %T", ctx)
    }
    token, err := s.getToken(gc, RefreshTokenName)
    if err != nil {
        return RefreshAccessToken401Response{}, nil
    }
    if err = checkRefreshToken(s, token); err != nil {
        return RefreshAccessToken401Response{}, nil
    }
    u, err := getUserBySubject(s, token)
    if err != nil {
        return RefreshAccessToken401Response{}, nil
    }

    // generate access token and refresh token
    at, err := issueAccessToken(s, u)
    if err != nil {
        log.Debugf("failed to issue access token: %v", err)
        return RefreshAccessToken401Response{}, nil
    }
    rt, err := issueRefreshToken(s, u)
    if err != nil {
        log.Debugf("failed to issue refresh token: %v", err)
        return RefreshAccessToken401Response{}, nil
    }
    gc.SetSameSite(http.SameSiteStrictMode)
    s.setCookie(gc, AccessTokenName, at, "/", 3600)
    s.setCookie(gc, RefreshTokenName, rt, "/access-token", 7*24*3600)
    return RefreshAccessToken204Response{}, nil
}
