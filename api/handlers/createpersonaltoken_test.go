package handlers

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
)

func Test_CreatePersonalToken_creates_a_personal_token(t *testing.T) {
	body := CreatePersonalTokenJSONBody{
		Description: "test_perm", Scopes: []string{"read", "write"}, Ttl: 3600,
	}
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/personal-tokens", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	actual := unmarshalResponse(t, CreatePersonalToken201JSONResponse{}, res)
	require.Equal(t, body.Description, actual.Description)
	require.GreaterOrEqual(t, actual.Id, uint64(1))
	require.GreaterOrEqual(t, *actual.CreatedAt, startTime)
	tt, err := svr.jwtTokenFromString(actual.Token)
	require.Nil(t, err)
	roles, err := tt.getRoles()
	require.Nil(t, err)
	require.Equal(t, []string{"root"}, *roles)
	scopes, err := tt.getScopes()
	require.Nil(t, err)
	require.Equal(t, body.Scopes, *scopes)
	jti, err := tt.getJtiBinary()
	require.Nil(t, err)
	row, err := db.PersonalToken.Query().
		Where(personaltoken.DescriptionEQ(body.Description)).
		Where(personaltoken.TokenEQ(jti)).
		First(context.Background())
	require.Nil(t, err)
	require.Equal(t, actual.Id, row.ID)
}

func Test_CreatePersonalToken_returns_401_if_non_user(t *testing.T) {
	body := CreatePersonalTokenJSONBody{
		Description: "test_perm", Scopes: []string{"read", "write"}, Ttl: 3600,
	}
	svr, engine, db, res := setupTestCase(t, false)
	req, err := svr.post("/personal-tokens", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.False(
		t,
		db.PersonalToken.Query().
			Where(personaltoken.DescriptionEQ(body.Description)).
			ExistX(context.Background()),
	)
}

func Test_CreatePersonalToken_returns_401_if_invalid_context_token(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	r, err := svr.CreatePersonalToken(
		gin.CreateTestContextOnly(res, engine),
		CreatePersonalTokenRequestObject{},
	)
	require.Nil(t, err)
	require.IsType(t, r, CreatePersonalToken401JSONResponse{})
}

func Test_CreatePersonalToken_returns_403_if_user_without_permission(t *testing.T) {
	body := CreatePersonalTokenJSONBody{
		Description: "test_perm", Scopes: []string{"read", "write"}, Ttl: 3600,
	}
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 2)
	req, err := svr.postAs(u, "/personal-tokens", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.False(
		t,
		db.PersonalToken.Query().
			Where(personaltoken.DescriptionEQ(body.Description)).
			ExistX(context.Background()),
	)
}

func Test_CreatePersonalToken_reports_422_if_no_description(t *testing.T) {
	body := CreatePersonalTokenJSONBody{
		Scopes: []string{"read", "write"}, Ttl: 3600,
	}
	svr, engine, db, res := setupTestCase(t, false)
	count := db.PersonalToken.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/personal-tokens", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bdescription\b.*\bminimum\b.*\b2`),
		res.Body.String(),
	)
	require.Equal(
		t, count, db.PersonalToken.Query().CountX(context.Background()),
	)
}

func Test_CreatePersonalToken_reports_422_if_description_too_long(t *testing.T) {
	body := CreatePersonalTokenJSONBody{
		Description: strings.Repeat("a", 256),
		Scopes:      []string{"read", "write"},
		Ttl:         3600,
	}
	svr, engine, db, res := setupTestCase(t, false)
	count := db.PersonalToken.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/personal-tokens", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bdescription\b.*\bmaximum\b.*\b255`),
		res.Body.String(),
	)
	require.Equal(
		t, count, db.PersonalToken.Query().CountX(context.Background()),
	)
}

func Test_CreatePersonalToken_reports_422_if_no_scope(t *testing.T) {
	body := CreatePersonalTokenJSONBody{
		Description: "test_perm", Ttl: 3600,
	}
	svr, engine, db, res := setupTestCase(t, false)
	count := db.PersonalToken.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/personal-tokens", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bscopes\b.*\bnot\b.*\bnull`),
		res.Body.String(),
	)
	require.Equal(
		t, count, db.PersonalToken.Query().CountX(context.Background()),
	)
}

func Test_CreatePersonalToken_reports_422_if_no_ttl(t *testing.T) {
	body := CreatePersonalTokenJSONBody{
		Description: "test_perm", Scopes: []string{"read", "write"},
	}
	svr, engine, db, res := setupTestCase(t, false)
	count := db.PersonalToken.Query().CountX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/personal-tokens", body)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
	require.Regexp(
		t, regexp.MustCompile(`\bttl\b.*\bleast\b.*\b3600`),
		res.Body.String(),
	)
	require.Equal(
		t, count, db.PersonalToken.Query().CountX(context.Background()),
	)
}

func Test_CreatePersonalToken_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setupTestCase(t, false)
	_, err := svr.CreatePersonalToken(
		context.Background(), CreatePersonalTokenRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}

func Test_CreatePersonalToken_returns_500_if_db_error_unhandled(t *testing.T) {
	body := CreatePersonalTokenJSONBody{
		Description: "test_perm", Scopes: []string{"read", "write"}, Ttl: 3600,
	}
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.postAs(u, "/personal-tokens", body)
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
