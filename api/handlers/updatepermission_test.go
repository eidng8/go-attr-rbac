package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-utils"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/permission"
)

func Test_UpdatePermission_updates_name(t *testing.T) {
	name := "test_permission"
	body := UpdatePermissionJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, true)
	expected, err := db.Permission.Query().Where(permission.IDEQ(2)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/permission/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, UpdatePermission200JSONResponse{}, res)
	require.Equal(t, expected.ID, actual.Id)
	require.Equal(t, name, actual.Name)
	require.Equal(t, expected.Description, *actual.Description)
	require.Equal(t, expected.CreatedAt.Local(), actual.CreatedAt.Local())
	require.GreaterOrEqual(t, actual.UpdatedAt.Local(), startTime.Local())
	row, err := db.Permission.Query().Where(
		permission.IDEQ(expected.ID), permission.NameEQ(name),
		permission.DescriptionIsNil(),
	).First(context.Background())
	require.Nil(t, err)
	require.Equal(t, row.CreatedAt.Local(), actual.CreatedAt.Local())
}

func Test_UpdatePermission_updates_description(t *testing.T) {
	desc := "test_permission"
	body := UpdatePermissionJSONBody{Description: &desc}
	svr, engine, db, res := setupTestCase(t, true)
	expected, err := db.Permission.Query().Where(permission.IDEQ(2)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/permission/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, UpdatePermission200JSONResponse{}, res)
	require.Equal(t, expected.ID, actual.Id)
	require.Equal(t, expected.Name, actual.Name)
	require.Equal(t, desc, *actual.Description)
	require.Equal(t, expected.CreatedAt.Local(), actual.CreatedAt.Local())
	require.GreaterOrEqual(t, actual.UpdatedAt.Local(), startTime.Local())
	row, err := db.Permission.Query().Where(
		permission.IDEQ(2), permission.NameEQ(expected.Name),
		permission.DescriptionEQ(desc),
	).First(context.Background())
	require.Nil(t, err)
	require.Equal(t, row.CreatedAt.Local(), actual.CreatedAt.Local())
}

func Test_UpdatePermission_updates_a_permission_replaces_roles(t *testing.T) {
	body := UpdatePermissionJSONBody{Roles: &[]uint32{5, 6}}
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/permission/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(
		t, []uint32{5, 6},
		utils.Pluck(
			db.Permission.Query().Where(permission.IDEQ(2)).QueryRoles().
				AllX(context.Background()),
			ent.PluckRoleID,
		),
	)
}

func Test_UpdatePermission_returns_401_if_non_user(t *testing.T) {
	name := "test_permission"
	body := UpdatePermissionJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.Permission.Query().Where(permission.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	req, err := svr.patch("/permission/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.True(
		t,
		db.Permission.Query().Where(
			permission.IDEQ(expected.ID),
			permission.NameEQ(expected.Name),
			permission.DescriptionIsNil(),
			permission.CreatedAtEQ(*expected.CreatedAt),
			permission.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdatePermission_returns_403_if_user_without_permission(t *testing.T) {
	name := "test_permission"
	body := UpdatePermissionJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.Permission.Query().Where(permission.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 2)
	req, err := svr.patchAs(u, "/permission/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.True(
		t,
		db.Permission.Query().Where(
			permission.IDEQ(expected.ID),
			permission.NameEQ(expected.Name),
			permission.DescriptionIsNil(),
			permission.CreatedAtEQ(*expected.CreatedAt),
			permission.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdatePermission_reports_422_if_request_empty(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/permission/2", UpdatePermissionJSONBody{})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
}

func Test_UpdatePermission_reports_404_if_permission_not_exists(t *testing.T) {
	name := "test_permission"
	body := UpdatePermissionJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/permission/12345", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 404, res.Code)
}
