package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/accesstoken"
)

func Test_RevokeAccessToken_clears_current_tokens(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := http.NewRequest(http.MethodDelete, "/access-token", nil)
	require.Nil(t, err)
	var at, rt string
	at, err = svr.issueAccessToken(u)
	require.Nil(t, err)
	req.AddCookie(
		&http.Cookie{
			Name:     accessTokenName,
			Value:    at,
			Path:     AccessTokenPath,
			Domain:   svr.Domain(),
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	rt, err = svr.issueRefreshToken(u)
	require.Nil(t, err)
	req.AddCookie(
		&http.Cookie{
			Name:     refreshTokenName,
			Value:    rt,
			Path:     RefreshTokenPath,
			Domain:   svr.Domain(),
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	engine.ServeHTTP(res, req)
	// check response headers
	require.Equal(t, http.StatusNoContent, res.Code)
	cat, crt := getTokensFromSetCookieHeaders(t, res)
	require.NotNil(t, cat)
	require.Equal(t, "", cat.Value)
	require.Equal(t, AccessTokenPath, cat.Path)
	require.Equal(t, -1, cat.MaxAge)
	require.Equal(t, http.SameSiteStrictMode, cat.SameSite)
	require.True(t, cat.HttpOnly)
	require.True(t, cat.Secure)
	require.NotNil(t, crt)
	require.Equal(t, "", crt.Value)
	require.Equal(t, RefreshTokenPath, crt.Path)
	require.Equal(t, -1, crt.MaxAge)
	require.Equal(t, http.SameSiteStrictMode, crt.SameSite)
	require.True(t, crt.HttpOnly)
	require.True(t, crt.Secure)
	// check database black list
	jwtas, err := svr.jwtTokenFromString(at)
	require.Nil(t, err)
	jwtab, err := jwtas.getJtiBinary()
	require.Nil(t, err)
	jwtrs, err := svr.jwtTokenFromString(rt)
	require.Nil(t, err)
	jwtrb, err := jwtrs.getJtiBinary()
	require.Nil(t, err)
	require.True(
		t,
		db.AccessToken.Query().Where(accesstoken.UserIDEQ(u.ID)).
			Where(accesstoken.AccessTokenEQ(jwtab)).
			Where(accesstoken.RefreshTokenEQ(jwtrb)).
			ExistX(context.Background()),
	)
	// make sure revoked tokens can't be used again
	reqc, err := http.NewRequest(http.MethodGet, "/access-token", nil)
	require.Nil(t, err)
	reqc.AddCookie(
		&http.Cookie{
			Name:     accessTokenName,
			Value:    at,
			Path:     AccessTokenPath,
			Domain:   svr.Domain(),
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	reqc.AddCookie(
		&http.Cookie{
			Name:     refreshTokenName,
			Value:    rt,
			Path:     RefreshTokenPath,
			Domain:   svr.Domain(),
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	resc := httptest.NewRecorder()
	engine.ServeHTTP(resc, reqc)
	require.Equal(t, http.StatusUnauthorized, resc.Code)
}

func Test_RevokeAccessToken_returns_401_if_invalid_access_token(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := http.NewRequest(http.MethodDelete, "/access-token", nil)
	require.Nil(t, err)
	req.AddCookie(
		&http.Cookie{
			Name:     accessTokenName,
			Value:    "invalid token",
			Path:     AccessTokenPath,
			Domain:   svr.Domain(),
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_RevokeAccessToken_returns_401_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setupTestCase(t, false)
	res, err := svr.RevokeAccessToken(
		context.Background(), RevokeAccessTokenRequestObject{},
	)
	require.Nil(t, err)
	require.IsType(t, RevokeAccessToken401JSONResponse{}, res)
}
