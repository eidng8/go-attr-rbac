package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/user"
)

func Test_CheckAccessToken_returns_204_for_valid_token(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr, err := db.User.Query().WithRoles().Where(user.IDEQ(1)).
		Only(context.Background())
	require.Nil(t, err)
	req, err := svr.getAs(usr, "/access-token")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
}

func Test_CheckAccessToken_returns_204_for_valid_bearer_token(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr, err := db.User.Query().WithRoles().Where(user.IDEQ(1)).
		Only(context.Background())
	require.Nil(t, err)
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

func Test_CheckAccessToken_returns_401_if_no_token_role_is_null(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.getAs(usr, "/access-token")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_returns_401_if_no_token_role_mismatch(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 1)
	roles := db.Role.Query().Limit(3).AllX(context.Background())
	usr.Edges.Roles = roles
	req, err := svr.getAs(usr, "/access-token")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_CheckAccessToken_returns_401_if_invalid_header(t *testing.T) {
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

func Test_CheckAccessToken_returns_401_if_invalid_bearer_token(t *testing.T) {
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

func Test_CheckAccessToken_returns_401_if_invalid_jti(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	_, claims, err := svr.buildTokenClaims(usr, 3600)
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

func Test_CheckAccessToken_returns_401_if_invalid_subject(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	_, claims, err := svr.buildTokenClaims(usr, 3600)
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

func Test_CheckAccessToken_returns_401_if_invalid_issuer(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	_, claims, err := svr.buildTokenClaims(usr, 3600)
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

func Test_CheckAccessToken_returns_401_if_invalid_audience(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	_, claims, err := svr.buildTokenClaims(usr, 3600)
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

func Test_CheckAccessToken_returns_401_if_premature_token(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	_, claims, err := svr.buildTokenClaims(usr, 3600)
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

func Test_CheckAccessToken_returns_401_if_expired_token(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 2)
	_, claims, err := svr.buildTokenClaims(usr, 3600)
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

func Test_CheckAccessToken_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setup(t, false)
	_, err := svr.CheckAccessToken(
		context.Background(), CheckAccessTokenRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}

func Test_CheckAccessToken_returns_401_if_invalid_cookie(t *testing.T) {
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

func Test_CheckAccessToken_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	usr := getUserById(t, db, 3)
	req, err := svr.getAs(usr, "/access-token")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_CheckAccessToken_returns_401_if_invalid_context_token(t *testing.T) {
	svr, engine, _, res := setup(t, false)
	r, err := svr.CheckAccessToken(
		gin.CreateTestContextOnly(res, engine),
		CheckAccessTokenRequestObject{},
	)
	require.Nil(t, err)
	require.IsType(t, r, CheckAccessToken401JSONResponse{})
}
