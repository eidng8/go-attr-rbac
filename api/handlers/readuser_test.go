package handlers

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ReadUser_returns_a_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/user/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, ReadUser200JSONResponse{}, res)
	require.Equal(t, uint64(2), actual.Id)
	require.Equal(t, "user0", actual.Username)
	require.NotNil(t, actual.Email)
}

func Test_ReadUser_returns_trashed_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	db.User.DeleteOneID(2).ExecX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/user/2?trashed=1")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, ReadUser200JSONResponse{}, res)
	require.Equal(t, uint64(2), actual.Id)
	require.Equal(t, "user0", actual.Username)
	require.GreaterOrEqual(t, *actual.DeletedAt, startTime)
}

func Test_ReadUser_returns_404_if_not_found(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/user/12345")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func Test_ReadUser_returns_404_if_soft_deleted(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	db.User.DeleteOneID(2).ExecX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/user/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func Test_ReadUser_returns_a_user_without_email(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	n := db.User.Create().SetUsername("test user").SetPassword("test password").
		SaveX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, fmt.Sprintf("/user/%d", n.ID))
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, ReadUser200JSONResponse{}, res)
	require.Equal(t, n.ID, actual.Id)
	require.Equal(t, "test user", actual.Username)
	require.Nil(t, actual.Email)
}

func Test_ReadUser_returns_401_if_non_user(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.get("/user/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_ReadUser_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 3)
	req, err := svr.getAs(u, "/user/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_ReadUser_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/user/2")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
