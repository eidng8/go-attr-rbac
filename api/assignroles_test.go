package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-utils"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/role"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

func Test_AssignRoles_attaches_role_to_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	rows, err := db.Role.Query().Select(role.FieldID).Limit(3).
		Order(role.ByID()).All(context.Background())
	require.Nil(t, err)
	require.NotEmpty(t, rows)
	ids := utils.Pluck(rows, pluckRoleId)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/user/3/roles", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	rows, err = db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		Select(role.FieldID).Limit(3).Order(role.ByID()).
		All(context.Background())
	require.Nil(t, err)
	require.Equal(t, ids, utils.Pluck(rows, pluckRoleId))
}

func Test_AssignRoles_reports_422_if_role_is_empty(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/user/3/roles", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
}

func Test_AssignRoles_reports_404_if_user_not_found(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/user/123/roles", []int{1})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func Test_AssignRoles_reports_400_if_role_not_found(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/user/2/roles", []int{1234})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
}

func Test_AssignRoles_returns_401_if_non_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	rows, err := db.Role.Query().Select(role.FieldID).Limit(3).
		Order(role.ByID()).All(context.Background())
	require.Nil(t, err)
	require.NotEmpty(t, rows)
	ids := utils.Pluck(rows, pluckRoleId)
	req, err := svr.post("/user/3/roles", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	ex, err := db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		Exist(context.Background())
	require.Nil(t, err)
	require.False(t, ex)
}

func Test_AssignRoles_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	rows, err := db.Role.Query().Select(role.FieldID).Limit(3).
		Order(role.ByID()).All(context.Background())
	require.Nil(t, err)
	require.NotEmpty(t, rows)
	ids := utils.Pluck(rows, pluckRoleId)
	usr := getUserById(t, db, 3)
	req, err := svr.postAs(usr, "/user/3/roles", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	ex, err := db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		Exist(context.Background())
	require.Nil(t, err)
	require.False(t, ex)
}

func Test_AssignRoles_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/user/2/roles", []int{1})
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
