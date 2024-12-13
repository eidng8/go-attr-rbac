package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-ent/paginate"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

func Test_ListRole_returns_10_per_page(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListRolePaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Role]{
			Total:        11,
			PerPage:      10,
			CurrentPage:  1,
			LastPage:     2,
			FirstPageUrl: svr.baseUrl + "/roles?page=1&per_page=10",
			LastPageUrl:  svr.baseUrl + "/roles?page=2&per_page=10",
			NextPageUrl:  svr.baseUrl + "/roles?page=2&per_page=10",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/roles",
			From:         1,
			To:           10,
			Data: db.Role.Query().Order(role.ByID()).Limit(10).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 10)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/roles")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListRole_returns_5_per_page(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListRolePaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Role]{
			Total:        11,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     3,
			FirstPageUrl: svr.baseUrl + "/roles?page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/roles?page=3&per_page=5",
			NextPageUrl:  svr.baseUrl + "/roles?page=2&per_page=5",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/roles",
			From:         1,
			To:           5,
			Data: db.Role.Query().Order(role.ByID()).Limit(5).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/roles?per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListRole_returns_2nd_page(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListRolePaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Role]{
			Total:        11,
			PerPage:      5,
			CurrentPage:  2,
			LastPage:     3,
			FirstPageUrl: svr.baseUrl + "/roles?page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/roles?page=3&per_page=5",
			NextPageUrl:  svr.baseUrl + "/roles?page=3&per_page=5",
			PrevPageUrl:  svr.baseUrl + "/roles?page=1&per_page=5",
			Path:         svr.baseUrl + "/roles",
			From:         6,
			To:           10,
			Data: db.Role.Query().Order(role.ByID()).Limit(5).Offset(5).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/roles?page=2&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListRole_filters_by_name(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListRolePaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Role]{
			Total:        10,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     2,
			FirstPageUrl: svr.baseUrl + "/roles?name=role&page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/roles?name=role&page=2&per_page=5",
			NextPageUrl:  svr.baseUrl + "/roles?name=role&page=2&per_page=5",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/roles",
			From:         1,
			To:           5,
			Data: db.Role.Query().Order(role.ByID()).Limit(5).
				Where(role.NameHasPrefix("role")).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/roles?name=role&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListRole_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setupTestCase(t, false)
	_, err := svr.ListRole(context.Background(), ListRoleRequestObject{})
	require.ErrorIs(t, err, errInvalidContext)
}

func Test_ListRole_returns_401_if_non_user(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.get("/roles")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_ListRole_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 3)
	req, err := svr.getAs(u, "/roles")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_ListRole_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/roles")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
