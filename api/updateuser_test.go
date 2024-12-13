package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/eidng8/go-utils"
	"github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

func Test_UpdateUser_updates_email(t *testing.T) {
	email := types.Email("test@example.com")
	body := UpdateUserJSONBody{Email: &email}
	svr, engine, db, res := setupTestCase(t, true)
	expected, err := db.User.Query().Where(user.IDEQ(2)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/user/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, UpdateUser200JSONResponse{}, res)
	require.Equal(t, expected.ID, actual.Id)
	require.Equal(t, email, *actual.Email)
	require.Equal(t, expected.Username, actual.Username)
	require.Equal(t, userAttrFromMap(*expected.Attr), actual.Attr)
	require.Equal(t, expected.CreatedAt.Local(), actual.CreatedAt.Local())
	require.GreaterOrEqual(t, actual.UpdatedAt.Local(), startTime.Local())
	row, err := db.User.Query().
		Where(user.Username(expected.Username)).
		Where(user.PasswordEQ(expected.Password)).
		Where(user.IDEQ(2), user.EmailEQ(string(email))).
		First(context.Background())
	require.Nil(t, err)
	require.Equal(t, row.CreatedAt.Local(), actual.CreatedAt.Local())
}

func Test_UpdateUser_updates_a_user_with_attr(t *testing.T) {
	attr := userAttrOf(321, 123)
	body := UpdateUserJSONBody{Attr: attr}
	svr, engine, db, res := setupTestCase(t, true)
	expected, err := db.User.Query().Where(user.IDEQ(2)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/user/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, UpdateUser200JSONResponse{}, res)
	require.Equal(t, expected.ID, actual.Id)
	require.Equal(t, expected.Username, actual.Username)
	require.Equal(t, *expected.Email, string(*actual.Email))
	require.Equal(t, attr, actual.Attr)
	require.Equal(t, expected.CreatedAt.Local(), actual.CreatedAt.Local())
	require.GreaterOrEqual(t, actual.UpdatedAt.Local(), startTime.Local())
	row, err := db.User.Query().Where(user.IDEQ(2), user.AttrNotNil()).
		First(context.Background())
	require.Nil(t, err)
	require.Equal(t, userAttrToMap(*attr), row.Attr)
}

func Test_UpdateUser_updates_a_user_replaces_roles(t *testing.T) {
	body := UpdateUserJSONBody{Roles: &[]uint32{5, 6}}
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/user/2", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(
		t, []uint32{5, 6},
		utils.Pluck(
			db.User.Query().Where(user.IDEQ(2)).QueryRoles().
				AllX(context.Background()),
			ent.PluckRoleID,
		),
	)
}

func Test_UpdateUser_returns_401_if_non_user(t *testing.T) {
	email := types.Email("test@example.com")
	body := UpdateUserJSONBody{Email: &email}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.User.Query().Where(user.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	req, err := svr.patch("/user/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.True(
		t,
		db.User.Query().Where(
			user.IDEQ(expected.ID), user.UsernameEQ(expected.Username),
			user.PasswordEQ(expected.Password), user.EmailEQ(*expected.Email),
			user.CreatedAtEQ(*expected.CreatedAt), user.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateUser_returns_403_if_user_without_permission(t *testing.T) {
	email := types.Email("test@example.com")
	body := UpdateUserJSONBody{Email: &email}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.User.Query().Where(user.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 2)
	req, err := svr.patchAs(u, "/user/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.True(
		t,
		db.User.Query().Where(
			user.IDEQ(expected.ID), user.UsernameEQ(expected.Username),
			user.PasswordEQ(expected.Password), user.EmailEQ(*expected.Email),
			user.CreatedAtEQ(*expected.CreatedAt), user.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateUser_reports_422_if_email_malformed(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.User.Query().Where(user.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := http.NewRequest(
		http.MethodPatch, "/user/3",
		io.NopCloser(strings.NewReader(`{"email":"123"}`)),
	)
	require.Nil(t, err)
	at, err := svr.issueAccessToken(u)
	require.Nil(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(
		&http.Cookie{
			Name:     accessTokenName,
			Value:    at,
			Path:     AccessTokenPath,
			Domain:   svr.Domain(),
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
	)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
	require.Contains(t, "email", res.Body.String())
	require.True(
		t,
		db.User.Query().Where(
			user.IDEQ(expected.ID), user.UsernameEQ(expected.Username),
			user.PasswordEQ(expected.Password), user.EmailEQ(*expected.Email),
			user.CreatedAtEQ(*expected.CreatedAt), user.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateUser_reports_422_if_dept_invalid(t *testing.T) {
	attr := userAttrOf(0, 0)
	body := UpdateUserJSONBody{Attr: attr}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.User.Query().Where(user.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/user/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
	require.Contains(t, res.Body.String(), "dept")
	require.True(
		t,
		db.User.Query().Where(
			user.IDEQ(expected.ID), user.UsernameEQ(expected.Username),
			user.PasswordEQ(expected.Password), user.EmailEQ(*expected.Email),
			user.CreatedAtEQ(*expected.CreatedAt), user.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateUser_reports_422_if_level_invalid(t *testing.T) {
	attr := userAttrOf(1, 0)
	body := UpdateUserJSONBody{Attr: attr}
	svr, engine, db, res := setupTestCase(t, false)
	expected, err := db.User.Query().Where(user.IDEQ(3)).
		First(context.Background())
	require.Nil(t, err)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/user/3", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
	require.Contains(t, res.Body.String(), "level")
	require.True(
		t,
		db.User.Query().Where(
			user.IDEQ(expected.ID), user.UsernameEQ(expected.Username),
			user.PasswordEQ(expected.Password), user.EmailEQ(*expected.Email),
			user.CreatedAtEQ(*expected.CreatedAt), user.UpdatedAtIsNil(),
		).ExistX(context.Background()),
	)
}

func Test_UpdateUser_reports_422_if_request_empty(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/user/2", UpdateUserJSONBody{})
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
}

func Test_UpdateUser_reports_404_if_user_not_exists(t *testing.T) {
	email := types.Email("test@example.com")
	body := UpdateUserJSONBody{Email: &email}
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/user/12345", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 404, res.Code)
}

func Test_UpdateUser_returns_500_if_db_error_unhandled(t *testing.T) {
	email := types.Email("test@example.com")
	body := UpdateUserJSONBody{Email: &email}
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.patchAs(u, "/user/2", body)
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
