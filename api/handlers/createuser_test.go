package handlers

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/eidng8/go-utils"
	"github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

func Test_CreateUser_creates_a_user(t *testing.T) {
	body := CreateUserJSONBody{Username: "test_user", Password: "Abcd_1234"}
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	actual := unmarshalResponse(t, User{}, res)
	require.Equal(t, body.Username, actual.Username)
	require.Greater(t, actual.Id, uint64(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row := db.User.Query().Where(user.UsernameEQ(body.Username)).
		FirstX(context.Background())
	require.Equal(t, actual.Id, row.ID)
	eq, err := utils.ComparePassword(body.Password, row.Password)
	require.Nil(t, err)
	require.True(t, eq)
}

func Test_CreateUser_creates_a_user_with_email(t *testing.T) {
	email := types.Email("test@sample.com")
	body := CreateUserJSONBody{
		Username: "test_user", Password: "Abcd_1234", Email: &email,
	}
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	actual := User{}
	require.Nil(t, json.Unmarshal([]byte(res.Body.String()), &actual))
	require.Equal(t, body.Username, actual.Username)
	require.Equal(t, body.Email, actual.Email)
	require.Greater(t, actual.Id, uint64(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row := db.User.Query().Where(user.UsernameEQ(body.Username)).
		Where(user.EmailEQ("test@sample.com")).
		FirstX(context.Background())
	require.Equal(t, actual.Id, row.ID)
}

func Test_CreateUser_creates_a_user_with_roles(t *testing.T) {
	body := CreateUserJSONBody{
		Username: "test_user", Password: "Abcd_1234", Roles: &[]uint32{2, 3},
	}
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	actual := User{}
	require.Nil(t, json.Unmarshal([]byte(res.Body.String()), &actual))
	require.Equal(t, body.Username, actual.Username)
	row := db.User.Query().Where(user.UsernameEQ(body.Username)).
		WithRoles().FirstX(context.Background())
	require.Equal(t, actual.Id, row.ID)
	ris := utils.Pluck(row.Edges.Roles, ent.PluckRoleID)
	slices.Sort(ris)
	require.Equal(t, []uint32{2, 3}, ris)
	rns := utils.Pluck(row.Edges.Roles, ent.PluckRoleName)
	slices.Sort(rns)
	require.Equal(t, []string{"role 0", "role 1"}, rns)
}

func Test_CreateUser_creates_a_user_with_attr(t *testing.T) {
	body := CreateUserJSONBody{
		Username: "test_user", Password: "Abcd_1234", Attr: &struct {
			Dept  uint32 `json:"dept"`
			Level uint8  `json:"level"`
		}{Dept: 321, Level: 123},
	}
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	actual := User{}
	require.Nil(t, json.Unmarshal([]byte(res.Body.String()), &actual))
	require.Equal(t, body.Username, actual.Username)
	require.Equal(t, body.Email, actual.Email)
	require.Greater(t, actual.Id, uint64(numFixtures))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	row := db.User.Query().Where(user.UsernameEQ(body.Username)).
		FirstX(context.Background())
	require.Equal(t, actual.Id, row.ID)
	require.Equal(t, float64(321), (*row.Attr)["dept"])
	require.Equal(t, float64(123), (*row.Attr)["level"])
}

func Test_CreateUser_denies_non_user(t *testing.T) {
	body := CreateUserJSONBody{Username: "test_user", Password: "Abcd_1234"}
	svr, engine, db, res := setup(t, false)
	req, err := svr.post("/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.False(
		t,
		db.User.Query().Where(user.UsernameEQ(body.Username)).
			ExistX(context.Background()),
	)
}

func Test_CreateUser_denies_user_without_permission(t *testing.T) {
	body := CreateUserJSONBody{Username: "test_user", Password: "Abcd_1234"}
	svr, engine, db, res := setup(t, false)
	u := getUserById(t, db, 2)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.False(
		t,
		db.User.Query().Where(user.UsernameEQ(body.Username)).
			ExistX(context.Background()),
	)
}

func Test_CreateUser_reports_422_if_no_username(t *testing.T) {
	body := CreateUserJSONBody{Password: "Abcd_1234"}
	svr, engine, db, res := setup(t, false)
	count := db.User.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\busername\b.*\bminimum\b.*\b2`),
		res.Body.String(),
	)
	require.Equal(t, count, db.User.Query().CountX(context.Background()))
}

func Test_CreateUser_reports_422_if_name_too_long(t *testing.T) {
	body := CreateUserJSONBody{
		Username: strings.Repeat("a", 256), Password: "Abcd_1234",
	}
	svr, engine, db, res := setup(t, false)
	count := db.User.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\busername\b.*\bmaximum\b.*\b255`),
		res.Body.String(),
	)
	require.Equal(t, count, db.User.Query().CountX(context.Background()))
}

func Test_CreateUser_reports_422_if_no_password(t *testing.T) {
	body := CreateUserJSONBody{Username: "test_user"}
	svr, engine, db, res := setup(t, false)
	count := db.User.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bpassword\b.*\bminimum\b.*\b8`),
		res.Body.String(),
	)
	require.Equal(t, count, db.User.Query().CountX(context.Background()))
}

func Test_CreateUser_reports_422_if_password_too_long(t *testing.T) {
	body := CreateUserJSONBody{
		Username: "test_user", Password: strings.Repeat("a", 256),
	}
	svr, engine, db, res := setup(t, false)
	count := db.User.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bpassword\b.*\bmaximum\b.*\b72`),
		res.Body.String(),
	)
	require.Equal(t, count, db.User.Query().CountX(context.Background()))
}

func Test_CreateUser_reports_422_if_password_too_simple(t *testing.T) {
	passwords := []string{
		"abcdefgh", "ABCDEFGH", "12345678", "#?!abcdE", "#?!123456",
	}
	svr, engine, db, res := setup(t, false)
	count := db.User.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	for _, pass := range passwords {
		t.Run(
			"password rule", func(t *testing.T) {
				body := CreateUserJSONBody{
					Username: "test_user", Password: pass,
				}
				req, err := svr.postAs(u, "/users", body)
				require.Nil(t, err)
				engine.ServeHTTP(res, req)
				require.Equal(t, 400, res.Code)
				require.Contains(t, res.Body.String(), "password must ")
				require.Equal(
					t, count, db.User.Query().CountX(context.Background()),
				)
			},
		)
	}
}

func Test_CreateUser_reports_400_if_user_exists(t *testing.T) {
	body := CreateUserJSONBody{Username: "root", Password: "Abcd_1234"}
	svr, engine, db, res := setup(t, false)
	count := db.User.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/users", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 400, res.Code)
	expected := map[string]interface{}{
		"code":   http.StatusBadRequest,
		"errors": "user already exists",
		"status": "error",
	}
	requireJsonEqualsString(t, expected, res.Body.String())
	require.Equal(t, count, db.User.Query().CountX(context.Background()))
}