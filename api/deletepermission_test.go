package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/permission"
)

func Test_DeletePermission_deletes_a_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/permission/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	require.False(
		t, db.Permission.Query().Where(permission.IDEQ(2)).
			ExistX(context.Background()),
	)
}

func Test_DeletePermission_returns_401_if_non_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	req, err := svr.delete("/permission/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.True(
		t, db.Permission.Query().Where(permission.IDEQ(2)).
			ExistX(context.Background()),
	)
}

func Test_DeletePermission_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 2)
	req, err := svr.deleteAs(u, "/permission/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.True(
		t, db.Permission.Query().Where(permission.IDEQ(2)).
			ExistX(context.Background()),
	)
}

func Test_DeletePermission_reports_404_if_user_exists(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/permission/12345")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 404, res.Code)
}

func Test_DeletePermission_reports_422_if_invalid_id(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/permission/a")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
}

func Test_DeletePermission_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/permission/2")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
