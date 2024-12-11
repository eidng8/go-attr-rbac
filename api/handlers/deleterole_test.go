package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/role"
)

func Test_DeleteRole_deletes_a_role(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/role/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	require.False(
		t, db.Role.Query().Where(role.IDEQ(2)).ExistX(context.Background()),
	)
}

func Test_DeleteRole_denies_non_user(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	req, err := svr.delete("/role/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.True(
		t, db.Role.Query().Where(role.IDEQ(2)).ExistX(context.Background()),
	)
}

func Test_DeleteRole_denies_user_without_permission(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	u := getUserById(t, db, 2)
	req, err := svr.deleteAs(u, "/role/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.True(
		t, db.Role.Query().Where(role.IDEQ(2)).ExistX(context.Background()),
	)
}

func Test_DeleteRole_reports_404_if_user_exists(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/role/12345")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 404, res.Code)
}

func Test_DeleteRole_reports_422_if_invalid_id(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/role/a")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
}
