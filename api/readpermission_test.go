package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ReadPermission_returns_a_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permission/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, ReadPermission200JSONResponse{}, res)
	require.Equal(t, uint32(2), actual.Id)
	require.Equal(t, "auth:CheckAccessToken", actual.Name)
}

func Test_ReadPermission_returns_404_if_not_found(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permission/12345")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func Test_ReadPermission_returns_401_if_non_user(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.get("/permission/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_ReadPermission_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 3)
	req, err := svr.getAs(u, "/permission/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_ReadPermission_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permission/2")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}