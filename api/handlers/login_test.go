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
	svr, engine, db, res := setupTestCase(t, true)
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

func Test_Login_returns_401_if_password_wrong(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	email := types.Email("test@sample.com")
	_, err := createUser(
		context.Background(), db.User.Create(), CreateUserJSONBody{
			Username: "test",
			Password: "Test_123",
			Email:    &email,
		},
	)
	require.Nil(t, err)
	req, err := svr.post(
		"/login", LoginJSONRequestBody{Username: "test", Password: "test"},
	)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_Login_returns_401_if_user_not_exist(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.post(
		"/login",
		LoginJSONRequestBody{Username: "not exist", Password: "test"},
	)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_Login_returns_401_if_invalid_password(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	_, err := db.ExecContext(
		context.Background(),
		"INSERT INTO users (username, password) VALUES ('test', 'test')",
	)
	require.Nil(t, err)
	req, err := svr.post(
		"/login",
		LoginJSONRequestBody{Username: "test", Password: "test"},
	)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_Login_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setupTestCase(t, false)
	_, err := svr.Login(
		context.Background(), LoginRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}

func Test_Login_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.post(
		"/login", LoginJSONRequestBody{Username: "test", Password: "Test_123"},
	)
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
