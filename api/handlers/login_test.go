package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/api"
)

func Test_Login_sets_cookies(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	email := types.Email("test@sample.com")
	u, err := createUser(
		context.Background(), db.User.Create(), CreateUserJSONBody{
			Username: "test",
			Password: "Test_123",
			Email:    &email,
		},
	)
	require.Nil(t, err)
	req, err := svr.post(
		"/login", LoginJSONRequestBody{Username: "test", Password: "Test_123"},
	)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 200, res.Code)
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
	requireJsonEqualsString(
		t, Login200JSONResponse{
			Id: u.ID, Username: "test", Email: &email, CreatedAt: u.CreatedAt,
		}, res.Body.String(),
	)
}
