package handlers

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/eidng8/go-utils"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

func Test_UpdateRole_updates_a_role(t *testing.T) {
	name := "test_role"
	body := UpdateRoleJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, true)
	expected, err := db.Role.Query().Where(role.IDEQ(2)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, UpdateRole200JSONResponse{}, res)
	require.Equal(t, expected.ID, actual.Id)
	require.Equal(t, name, actual.Name)
	require.Equal(t, expected.Description, *actual.Description)
	require.Equal(t, expected.CreatedAt.Local(), actual.CreatedAt.Local())
	require.GreaterOrEqual(t, actual.UpdatedAt.Local(), startTime.Local())
	row, err := db.Role.Query().Where(role.IDEQ(2), role.NameEQ(name)).
		Where(role.DescriptionEQ(expected.Description)).
		First(context.Background())
	require.Nil(t, err)
	require.Equal(t, row.CreatedAt.Local(), actual.CreatedAt.Local())
}

func Test_UpdateRole_updates_a_role_with_description(t *testing.T) {
	desc := "test descriptions"
	body := UpdateRoleJSONBody{Description: &desc}
	svr, engine, db, res := setupTestCase(t, true)
	expected, err := db.Role.Query().Where(role.IDEQ(2)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, UpdateRole200JSONResponse{}, res)
	require.Equal(t, expected.ID, actual.Id)
	require.Equal(t, expected.Name, actual.Name)
	require.Equal(t, desc, *actual.Description)
	require.Equal(t, expected.CreatedAt.Local(), actual.CreatedAt.Local())
	require.GreaterOrEqual(t, actual.UpdatedAt.Local(), startTime.Local())
	row, err := db.Role.Query().Where(
		role.IDEQ(2), role.Description(desc), role.NameEQ(expected.Name),
	).First(context.Background())
	require.Nil(t, err)
	require.Equal(t, row.CreatedAt.Local(), actual.CreatedAt.Local())
}

func Test_UpdateRole_updates_a_role_replaces_permissions(t *testing.T) {
	body := UpdateRoleJSONBody{Permissions: &[]uint32{5, 6}}
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(
		t, []uint32{5, 6},
		utils.Pluck(
			db.Role.Query().Where(role.IDEQ(2)).QueryPermissions().
				AllX(context.Background()),
			ent.PluckPermissionID,
		),
	)
}

func Test_UpdateRole_updates_a_role_replaces_users(t *testing.T) {
	body := UpdateRoleJSONBody{Users: &[]uint64{5, 6}}
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(
		t, []uint64{5, 6},
		utils.Pluck(
			db.Role.Query().Where(role.IDEQ(2)).QueryUsers().
				AllX(context.Background()),
			ent.PluckUserID,
		),
	)
}

func Test_UpdateRole_returns_401_if_non_user(t *testing.T) {
	name := "test name"
	body := UpdateRoleJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.Role.Query().Where(role.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	req, err := svr.patch("/role/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.True(
		t,
		db.Role.Query().Where(
			role.IDEQ(expected.ID), role.NameEQ(expected.Name),
			role.DescriptionEQ(expected.Description),
			role.CreatedAtEQ(*expected.CreatedAt), role.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateRole_returns_403_if_user_without_permission(t *testing.T) {
	name := "test name"
	body := UpdateRoleJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.Role.Query().Where(role.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 2)
	req, err := svr.patchAs(u, "/role/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.True(
		t,
		db.Role.Query().Where(
			role.IDEQ(expected.ID), role.NameEQ(expected.Name),
			role.DescriptionEQ(expected.Description),
			role.CreatedAtEQ(*expected.CreatedAt), role.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateRole_reports_422_if_name_too_short(t *testing.T) {
	name := ""
	body := UpdateRoleJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.Role.Query().Where(role.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bname\b.*\bminimum\b.*\b1`), res.Body.String(),
	)
	require.True(
		t,
		db.Role.Query().Where(
			role.IDEQ(expected.ID), role.NameEQ(expected.Name),
			role.DescriptionEQ(expected.Description),
			role.CreatedAtEQ(*expected.CreatedAt), role.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateRole_reports_422_if_name_too_long(t *testing.T) {
	name := strings.Repeat("a", 256)
	body := UpdateRoleJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.Role.Query().Where(role.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bname\b.*\bmaximum\b.*\b255`),
		res.Body.String(),
	)
	require.True(
		t,
		db.Role.Query().Where(
			role.IDEQ(expected.ID), role.NameEQ(expected.Name),
			role.DescriptionEQ(expected.Description),
			role.CreatedAtEQ(*expected.CreatedAt), role.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateRole_reports_422_if_description_too_long(t *testing.T) {
	desc := strings.Repeat("a", 256)
	body := UpdateRoleJSONBody{Description: &desc}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.Role.Query().Where(role.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bdescription\b.*\bmaximum\b.*\b255`),
		res.Body.String(),
	)
	require.True(
		t,
		db.Role.Query().Where(
			role.IDEQ(expected.ID), role.NameEQ(expected.Name),
			role.DescriptionEQ(expected.Description),
			role.CreatedAtEQ(*expected.CreatedAt), role.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateRole_reports_422_if_request_empty(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/2", UpdateRoleJSONBody{})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
}

func Test_UpdateRole_reports_404_if_role_not_exists(t *testing.T) {
	name := "test name"
	body := UpdateRoleJSONBody{Name: &name}
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/role/12345", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 404, res.Code)
}
