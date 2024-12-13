package api

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
	svr, engine, db, res := setupTestCase(t, true)
	rows, err := db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
		Select(permission.FieldID).Order(permission.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.NotEmpty(t, rows)
	ids := append(utils.Pluck(rows, pluckPermissionId), 10)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/role/2/permissions", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	rows, err = db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
		Select(permission.FieldID).Order(permission.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.Equal(t, ids, utils.Pluck(rows, pluckPermissionId))
}

func Test_AssignPermissions_reports_422_if_permission_is_empty(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	rows, err := db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
		Select(permission.FieldID).Order(permission.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.NotEmpty(t, rows)
	ids := utils.Pluck(rows, pluckPermissionId)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/role/2/permissions", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
	rows, err = db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
		Select(permission.FieldID).Order(permission.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.Equal(t, ids, utils.Pluck(rows, pluckPermissionId))
}

func Test_AssignPermissions_reports_400_if_role_not_found(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/role/123/permissions", []int{1})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
}

func Test_AssignPermissions_reports_400_if_permission_not_found(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/role/2/permissions", []int{1234})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
}

func Test_AssignPermissions_returns_401_if_non_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	rows, err := db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
		Select(permission.FieldID).Order(permission.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.NotEmpty(t, rows)
	ids := utils.Pluck(rows, pluckPermissionId)
	req, err := svr.post("/role/2/permissions", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	rows, err = db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
		Select(permission.FieldID).Order(permission.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.Equal(t, ids, utils.Pluck(rows, pluckPermissionId))
}

func Test_AssignPermissions_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	rows, err := db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
		Select(permission.FieldID).Order(permission.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.NotEmpty(t, rows)
	ids := utils.Pluck(rows, pluckPermissionId)
	usr := getUserById(t, db, 3)
	req, err := svr.postAs(usr, "/role/2/permissions", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	rows, err = db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
		Select(permission.FieldID).Order(permission.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.Equal(t, ids, utils.Pluck(rows, pluckPermissionId))
}

func Test_AssignPermissions_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/role/2/permissions", []int{1})
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
