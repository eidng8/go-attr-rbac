package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
)

func Test_HintUsers_returns_5_rows(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	svr.hintSize = 5
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/q/users?q=u")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	users := unmarshalResponse(t, []ent.User{}, res)
	require.Len(t, users, 5)
}

func Test_HintUsers_searches_by_email(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	svr.hintSize = 5
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/q/users?q=email")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	users := unmarshalResponse(t, []ent.User{}, res)
	require.Len(t, users, 5)
}

func Test_HintUsers_returns_401_if_non_user(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.get("/q/users?q=u")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_HintUsers_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 3)
	req, err := svr.getAs(u, "/q/users?q=u")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_HintUsers_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/q/users?q=u")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}