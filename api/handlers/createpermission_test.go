package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/permission"
)

func Test_CreatePermission_creates_a_permission(t *testing.T) {
	body := CreatePermissionJSONBody{Name: "test_perm"}
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/permissions", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := uuu(t, Permission{}, res)
	require.Equal(t, body.Name, actual.Name)
	require.Nil(t, body.Description)
	require.GreaterOrEqual(t, actual.Id, uint32(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row := db.Permission.Query().Where(permission.NameEQ(body.Name)).
		Where(permission.DescriptionIsNil()).
		FirstX(context.Background())
	require.Equal(t, actual.Id, row.ID)
}

func Test_CreatePermission_creates_a_permission_with_description(t *testing.T) {
	desc := "test descriptions"
	body := CreatePermissionJSONBody{Name: "test_perm", Description: &desc}
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/permissions", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := Permission{}
	require.Nil(t, json.Unmarshal([]byte(res.Body.String()), &actual))
	require.Equal(t, body.Name, actual.Name)
	require.Equal(t, body.Description, actual.Description)
	require.GreaterOrEqual(t, actual.Id, uint32(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row := db.Permission.Query().Where(permission.NameEQ(body.Name)).
		Where(permission.DescriptionEQ(*body.Description)).
		FirstX(context.Background())
	require.Equal(t, actual.Id, row.ID)
}

func Test_CreatePermission_denies_non_user(t *testing.T) {
	desc := "test descriptions"
	body := CreatePermissionJSONBody{Name: "test_perm", Description: &desc}
	svr, engine, db, res := setup(t, false)
	req, err := svr.post("/permissions", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.False(
		t,
		db.Permission.Query().Where(permission.NameEQ(body.Name)).
			Where(permission.DescriptionEQ(*body.Description)).
			ExistX(context.Background()),
	)
}

func Test_CreatePermission_denies_user_without_permission(t *testing.T) {
	desc := "test descriptions"
	body := CreatePermissionJSONBody{Name: "test_perm", Description: &desc}
	svr, engine, db, res := setup(t, false)
	u := getUserById(t, db, 2)
	req, err := svr.postAs(u, "/permissions", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.False(
		t,
		db.Permission.Query().Where(permission.NameEQ(body.Name)).
			Where(permission.DescriptionEQ(*body.Description)).
			ExistX(context.Background()),
	)
}

func Test_CreatePermission_reports_422_if_no_name(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	count := db.Permission.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/permissions", CreatePermissionJSONBody{})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Equal(t, count, db.Permission.Query().CountX(context.Background()))
}
