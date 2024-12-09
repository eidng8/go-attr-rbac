package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-utils"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/permission"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

func Test_AssignPermissions_attaches_permission_to_role(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	rows := db.Permission.Query().Select(permission.FieldID).Limit(3).
		Order(permission.ByID()).AllX(context.Background())
	ids := utils.Pluck(rows, pluckPermissionId)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/role/3/permissions", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	rows = db.Role.Query().Where(role.IDEQ(3)).QueryPermissions().
		Select(permission.FieldID).Limit(3).AllX(context.Background())
	require.Equal(t, ids, utils.Pluck(rows, pluckPermissionId))
}

func Test_AssignPermissions_reports_422_if_permission_is_empty(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/role/3/permissions", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
}

func Test_AssignPermissions_denies_non_user(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	rows := db.Permission.Query().Select(permission.FieldID).Limit(3).
		Order(permission.ByID()).AllX(context.Background())
	ids := utils.Pluck(rows, pluckPermissionId)
	req, err := svr.post("/role/3/permissions", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	ex := db.Role.Query().Where(role.IDEQ(3)).QueryPermissions().
		ExistX(context.Background())
	require.False(t, ex)
}

func Test_AssignPermissions_denies_user_without_permission(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	rows := db.Permission.Query().Select(permission.FieldID).Limit(3).
		Order(permission.ByID()).AllX(context.Background())
	ids := utils.Pluck(rows, pluckPermissionId)
	usr := getUserById(t, db, 3)
	req, err := svr.postAs(usr, "/role/3/permissions", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	ex := db.Role.Query().Where(role.IDEQ(3)).QueryPermissions().
		ExistX(context.Background())
	require.False(t, ex)
}
