package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/api"
)

func Test_RefreshAccessToken_sets_token_cookies(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/access-token/refresh", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	cat, crt := getTokensFromSetCookieHeaders(t, res)
	require.NotNil(t, cat)
	require.Equal(t, api.AccessTokenPath, cat.Path)
	require.Equal(t, 3600, cat.MaxAge)
	require.Equal(t, http.SameSiteStrictMode, cat.SameSite)
	require.True(t, cat.HttpOnly)
	require.True(t, cat.Secure)
	require.NotNil(t, crt)
	require.Equal(t, api.RefreshTokenPath, crt.Path)
	require.Equal(t, 7*24*3600, crt.MaxAge)
	require.Equal(t, http.SameSiteStrictMode, crt.SameSite)
	require.True(t, crt.HttpOnly)
	require.True(t, crt.Secure)
}

func Test_RefreshAccessToken_returns_401_if_invalid_refresh_token(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
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
			Path:     api.AccessTokenPath,
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
	svr, _, _, _ := setupTestCase(t, false)
	_, err := svr.RefreshAccessToken(
		context.Background(), RefreshAccessTokenRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}
