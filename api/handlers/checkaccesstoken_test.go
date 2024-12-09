package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func Test_CheckAccessToken_returns_204_for_valid_token(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.getAs(usr, "/access-token")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
}

func Test_CheckAccessToken_returns_204_for_valid_bearer_token(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	at, err := svr.issueAccessToken(usr)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer "+at)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
}

func Test_CheckAccessToken_returns_401_if_no_token(t *testing.T) {
	svr, engine, _, res := setup(t, false)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_invalid_header_returns_401(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	_, err := svr.issueAccessToken(usr)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer")
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_invalid_bearer_token_returns_401(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	_, err := svr.issueAccessToken(usr)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer 123456")
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_invalid_jti_returns_401(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	claims, err := svr.buildTokenClaims(usr, 3600)
	require.Nil(t, err)
	claims.ID = "123456"
	at, err := svr.issueJwtTokenWithClaims(jwt.SigningMethodHS256, claims)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer "+at)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_invalid_subject_returns_401(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	claims, err := svr.buildTokenClaims(usr, 3600)
	require.Nil(t, err)
	claims.Subject = "123456"
	at, err := svr.issueJwtTokenWithClaims(jwt.SigningMethodHS256, claims)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer "+at)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_invalid_issuer_returns_401(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	claims, err := svr.buildTokenClaims(usr, 3600)
	require.Nil(t, err)
	claims.Issuer = ""
	at, err := svr.issueJwtTokenWithClaims(jwt.SigningMethodHS256, claims)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer "+at)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_invalid_audience_returns_401(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	claims, err := svr.buildTokenClaims(usr, 3600)
	require.Nil(t, err)
	claims.Audience = nil
	at, err := svr.issueJwtTokenWithClaims(jwt.SigningMethodHS256, claims)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer "+at)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_premature_token_returns_401(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	claims, err := svr.buildTokenClaims(usr, 3600)
	require.Nil(t, err)
	claims.IssuedAt = &jwt.NumericDate{Time: time.Now().Add(3600 * time.Second)}
	at, err := svr.issueJwtTokenWithClaims(jwt.SigningMethodHS256, claims)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer "+at)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_expired_token_returns_401(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	claims, err := svr.buildTokenClaims(usr, 3600)
	require.Nil(t, err)
	claims.ExpiresAt = &jwt.NumericDate{Time: time.Now()}
	at, err := svr.issueJwtTokenWithClaims(jwt.SigningMethodHS256, claims)
	require.Nil(t, err)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	req.Header.Set("Authorization", "Bearer "+at)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_invalid_cookie_returns_401(t *testing.T) {
	svr, engine, _, res := setup(t, false)
	req, err := svr.get("/access-token")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	req.AddCookie(
		&http.Cookie{
			Name:     accessTokenName,
			Value:    "123456",
			Path:     "/",
			Domain:   "localhost",
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_denies_user_without_permission(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 3)
	req, err := svr.getAs(usr, "/access-token")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}
