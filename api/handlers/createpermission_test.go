package handlers

import (
	"context"
	"net/http"
	"regexp"
	"strings"
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
	require.Equal(t, http.StatusCreated, res.Code)
	actual := unmarshalResponse(t, Permission{}, res)
	require.Equal(t, body.Name, actual.Name)
	require.Nil(t, body.Description)
	require.Greater(t, actual.Id, uint32(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row, err := db.Permission.Query().Where(permission.NameEQ(body.Name)).
		Where(permission.DescriptionIsNil()).
		First(context.Background()) // FirstX() doesn't report not found error
	require.Nil(t, err)
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
	require.Equal(t, http.StatusCreated, res.Code)
	actual := Permission{}
	require.Nil(t, json.Unmarshal([]byte(res.Body.String()), &actual))
	require.Equal(t, body.Name, actual.Name)
	require.Equal(t, body.Description, actual.Description)
	require.Greater(t, actual.Id, uint32(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row, err := db.Permission.Query().Where(permission.NameEQ(body.Name)).
		Where(permission.DescriptionEQ(*body.Description)).
		First(context.Background())
	require.Nil(t, err)
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
	require.Regexp(
		t, regexp.MustCompile(`\bname\b.*\bminimum\b.*\b1`), res.Body.String(),
	)
	require.Equal(t, count, db.Permission.Query().CountX(context.Background()))
}

func Test_CreatePermission_reports_422_if_name_too_long(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	count := db.Permission.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	s := strings.Repeat("a", 256)
	req, err := svr.postAs(u, "/permissions", CreatePermissionJSONBody{Name: s})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bname\b.*\bmaximum\b.*\b255`),
		res.Body.String(),
	)
	require.Equal(t, count, db.Permission.Query().CountX(context.Background()))
}

func Test_CreatePermission_reports_422_if_description_too_long(t *testing.T) {
	desc := strings.Repeat("a", 256)
	body := CreatePermissionJSONBody{Name: "test_perm", Description: &desc}
	svr, engine, db, res := setup(t, false)
	count := db.Permission.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/permissions", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bdescription\b.*\bmaximum\b.*\b255`),
		res.Body.String(),
	)
	require.Equal(t, count, db.Permission.Query().CountX(context.Background()))
}

func Test_CreatePermission_reports_400_if_permission_exists(t *testing.T) {
	body := CreatePermissionJSONBody{Name: "auth:Login"}
	svr, engine, db, res := setup(t, false)
	count := db.Permission.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/permissions", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 400, res.Code)
	expected := map[string]interface{}{
		"code":   http.StatusBadRequest,
		"errors": "permission `auth:Login` already exists",
		"status": "error",
	}
	requireJsonEqualsString(t, expected, res.Body.String())
	require.Equal(t, count, db.Permission.Query().CountX(context.Background()))
}
