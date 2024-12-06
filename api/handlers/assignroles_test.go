package handlers

import (
	"context"
	"io"
	"net/http"
	"strings"
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
	json := "[" + utils.JoinInteger(ids, ",") + "]"
	body := io.NopCloser(strings.NewReader(json))
	usr := getUserById(t, db, 2)
	req := svr.requestAs(t, usr, http.MethodPost, "/user/3/roles", body)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	rows = db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		Select(role.FieldID).Limit(3).AllX(context.Background())
	require.Equal(t, ids, utils.Pluck(rows, pluckRoleId))
}

func Test_AssignRoles_denies_non_user(t *testing.T) {
	_, engine, db, res := setup(t, true)
	rows := db.Role.Query().Select(role.FieldID).Limit(3).
		Order(role.ByID()).AllX(context.Background())
	ids := utils.Pluck(rows, pluckRoleId)
	json := "[" + utils.JoinInteger(ids, ",") + "]"
	body := io.NopCloser(strings.NewReader(json))
	req, err := http.NewRequest(http.MethodPost, "/user/3/roles", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	ex := db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		ExistX(context.Background())
	require.False(t, ex)
}

func Test_AssignRoles_denies_user_without_permission(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	rows := db.Role.Query().Select(role.FieldID).Limit(3).
		Order(role.ByID()).AllX(context.Background())
	ids := utils.Pluck(rows, pluckRoleId)
	json := "[" + utils.JoinInteger(ids, ",") + "]"
	body := io.NopCloser(strings.NewReader(json))
	usr := getUserById(t, db, 3)
	req := svr.requestAs(t, usr, http.MethodPost, "/user/3/roles", body)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	ex := db.User.Query().Where(user.IDEQ(3)).QueryRoles().
		ExistX(context.Background())
	require.False(t, ex)
}
