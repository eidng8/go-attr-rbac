package handlers

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
	svr, engine, db, res := setup(t, true)
	rows := db.Role.Query().Select(role.FieldID).Limit(3).
		Order(role.ByID()).AllX(context.Background())
	ids := utils.Pluck(rows, pluckRoleId)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/user/3/roles", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	rows = db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		Select(role.FieldID).Limit(3).Order(role.ByID()).
		AllX(context.Background())
	require.Equal(t, ids, utils.Pluck(rows, pluckRoleId))
}

func Test_AssignRoles_reports_422_if_role_is_empty(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	usr := getUserById(t, db, 1)
	req, err := svr.postAs(usr, "/user/3/roles", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
}

func Test_AssignRoles_denies_non_user(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	rows := db.Role.Query().Select(role.FieldID).Limit(3).
		Order(role.ByID()).AllX(context.Background())
	ids := utils.Pluck(rows, pluckRoleId)
	req, err := svr.post("/user/3/roles", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	ex := db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		ExistX(context.Background())
	require.False(t, ex)
}

func Test_AssignRoles_denies_user_without_permission(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	rows := db.Role.Query().Select(role.FieldID).Limit(3).
		Order(role.ByID()).AllX(context.Background())
	ids := utils.Pluck(rows, pluckRoleId)
	usr := getUserById(t, db, 3)
	req, err := svr.postAs(usr, "/user/3/roles", ids)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	ex := db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		ExistX(context.Background())
	require.False(t, ex)
}
