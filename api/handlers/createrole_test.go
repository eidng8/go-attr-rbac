package handlers

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/role"
)

func Test_CreateRole_creates_a_role(t *testing.T) {
	body := CreateRoleJSONBody{Name: "test_role"}
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/roles", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	actual := unmarshalResponse(t, Role{}, res)
	require.Equal(t, body.Name, actual.Name)
	require.Nil(t, body.Description)
	require.Greater(t, actual.Id, uint32(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row := db.Role.Query().Where(role.NameEQ(body.Name)).
		Where(role.DescriptionIsNil()).
		FirstX(context.Background())
	require.Equal(t, actual.Id, row.ID)
}

func Test_CreateRole_creates_a_role_with_description(t *testing.T) {
	desc := "test descriptions"
	body := CreateRoleJSONBody{Name: "test_role", Description: &desc}
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/roles", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	actual := Role{}
	require.Nil(t, json.Unmarshal([]byte(res.Body.String()), &actual))
	require.Equal(t, body.Name, actual.Name)
	require.Equal(t, body.Description, actual.Description)
	require.Greater(t, actual.Id, uint32(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row := db.Role.Query().Where(role.NameEQ(body.Name)).
		Where(role.DescriptionEQ(*body.Description)).
		FirstX(context.Background())
	require.Equal(t, actual.Id, row.ID)
}

func Test_CreateRole_denies_non_user(t *testing.T) {
	desc := "test descriptions"
	body := CreateRoleJSONBody{Name: "test_role", Description: &desc}
	svr, engine, db, res := setup(t, false)
	req, err := svr.post("/roles", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.False(
		t,
		db.Role.Query().Where(role.NameEQ(body.Name)).
			Where(role.DescriptionEQ(*body.Description)).
			ExistX(context.Background()),
	)
}

func Test_CreateRole_denies_user_without_permission(t *testing.T) {
	desc := "test descriptions"
	body := CreateRoleJSONBody{Name: "test_role", Description: &desc}
	svr, engine, db, res := setup(t, false)
	u := getUserById(t, db, 2)
	req, err := svr.postAs(u, "/roles", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.False(
		t,
		db.Role.Query().Where(role.NameEQ(body.Name)).
			Where(role.DescriptionEQ(*body.Description)).
			ExistX(context.Background()),
	)
}

func Test_CreateRole_reports_422_if_no_name(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	count := db.Role.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/roles", CreateRoleJSONBody{})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bname\b.*\bminimum\b.*\b1`), res.Body.String(),
	)
	require.Equal(t, count, db.Role.Query().CountX(context.Background()))
}

func Test_CreateRole_reports_422_if_name_too_long(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	count := db.Role.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	s := strings.Repeat("a", 256)
	req, err := svr.postAs(u, "/roles", CreateRoleJSONBody{Name: s})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bname\b.*\bmaximum\b.*\b255`),
		res.Body.String(),
	)
	require.Equal(t, count, db.Role.Query().CountX(context.Background()))
}

func Test_CreateRole_reports_422_if_description_too_long(t *testing.T) {
	desc := strings.Repeat("a", 256)
	body := CreateRoleJSONBody{Name: "test_role", Description: &desc}
	svr, engine, db, res := setup(t, false)
	count := db.Role.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/roles", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bdescription\b.*\bmaximum\b.*\b255`),
		res.Body.String(),
	)
	require.Equal(t, count, db.Role.Query().CountX(context.Background()))
}

func Test_CreateRole_reports_400_if_role_exists(t *testing.T) {
	body := CreateRoleJSONBody{Name: "root"}
	svr, engine, db, res := setup(t, false)
	count := db.Role.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/roles", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 400, res.Code)
	expected := map[string]interface{}{
		"code":   http.StatusBadRequest,
		"errors": "role `root` already exists",
		"status": "error",
	}
	requireJsonEqualsString(t, expected, res.Body.String())
	require.Equal(t, count, db.Role.Query().CountX(context.Background()))
}
