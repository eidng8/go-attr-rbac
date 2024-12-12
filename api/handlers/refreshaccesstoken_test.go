package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-utils"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/api"
)

func Test_RefreshAccessToken_sets_token_cookies(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/access-token/refresh", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	cookies, err := utils.SliceMapFunc(
		res.Header().Values("Set-Cookie"),
		func(c string) (*http.Cookie, error) { return http.ParseSetCookie(c) },
	)
	require.Nil(t, err)
	at := utils.SliceFindFunc(
		cookies, func(c *http.Cookie) bool { return accessTokenName == c.Name },
	)
	require.NotNil(t, at)
	require.Equal(t, "/", at.Path)
	require.Equal(t, 3600, at.MaxAge)
	require.Equal(t, http.SameSiteStrictMode, at.SameSite)
	require.True(t, at.HttpOnly)
	require.True(t, at.Secure)
	rt := utils.SliceFindFunc(
		cookies,
		func(c *http.Cookie) bool { return refreshTokenName == c.Name },
	)
	require.NotNil(t, rt)
	require.Equal(t, api.RefreshTokenPath, rt.Path)
	require.Equal(t, 7*24*3600, rt.MaxAge)
	require.Equal(t, http.SameSiteStrictMode, rt.SameSite)
	require.True(t, rt.HttpOnly)
	require.True(t, rt.Secure)
}

func Test_RefreshAccessToken_returns_401_if_invalid_refresh_token(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := http.NewRequest(http.MethodPost, "/access-token/refresh", nil)
	require.Nil(t, err)
	var at string
	at, err = svr.issueAccessToken(u)
	require.Nil(t, err)
	req.AddCookie(
		&http.Cookie{
			Name:     accessTokenName,
			Value:    at,
			Path:     "/",
			Domain:   svr.Domain(),
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	req.AddCookie(
		&http.Cookie{
			Name:     refreshTokenName,
			Value:    "invalid token",
			Path:     api.RefreshTokenPath,
			Domain:   svr.Domain(),
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_RefreshAccessToken_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setup(t, false)
	_, err := svr.RefreshAccessToken(
		context.Background(), RefreshAccessTokenRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}
