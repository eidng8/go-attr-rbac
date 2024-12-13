package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-ent/paginate"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/permission"
)

func Test_ListPermission_returns_permission_list(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListPermissionPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Permission]{
			Total:        34,
			PerPage:      10,
			CurrentPage:  1,
			LastPage:     4,
			FirstPageUrl: svr.baseUrl + "/permissions?page=1&per_page=10",
			LastPageUrl:  svr.baseUrl + "/permissions?page=4&per_page=10",
			NextPageUrl:  svr.baseUrl + "/permissions?page=2&per_page=10",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/permissions",
			From:         1,
			To:           10,
			Data: db.Permission.Query().Order(permission.ByID()).Limit(10).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.Data, 10)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permissions")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListPermission_returns_permission_list_5_per_page(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListPermissionPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Permission]{
			Total:        34,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     7,
			FirstPageUrl: svr.baseUrl + "/permissions?page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/permissions?page=7&per_page=5",
			NextPageUrl:  svr.baseUrl + "/permissions?page=2&per_page=5",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/permissions",
			From:         1,
			To:           5,
			Data: db.Permission.Query().Order(permission.ByID()).Limit(5).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permissions?per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListPermission_returns_2nd_page(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListPermissionPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Permission]{
			Total:        34,
			PerPage:      5,
			CurrentPage:  2,
			LastPage:     7,
			FirstPageUrl: svr.baseUrl + "/permissions?page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/permissions?page=7&per_page=5",
			NextPageUrl:  svr.baseUrl + "/permissions?page=3&per_page=5",
			PrevPageUrl:  svr.baseUrl + "/permissions?page=1&per_page=5",
			Path:         svr.baseUrl + "/permissions",
			From:         6,
			To:           10,
			Data: db.Permission.Query().Order(permission.ByID()).Limit(5).
				Offset(5).AllX(context.Background()),
		},
	}
	require.Len(t, expected.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permissions?page=2&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListPermission_filters_by_name(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListPermissionPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Permission]{
			Total:        3,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     1,
			FirstPageUrl: svr.baseUrl + "/permissions?name=auth%3AHint&page=1&per_page=5",
			LastPageUrl:  "",
			NextPageUrl:  "",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/permissions",
			From:         1,
			To:           3,
			Data: db.Permission.Query().Order(permission.ByID()).Limit(5).
				Where(permission.NameHasPrefix("auth:Hint")).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 3)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permissions?name=auth%3AHint&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListPermission_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setupTestCase(t, false)
	_, err := svr.ListPermission(
		context.Background(), ListPermissionRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}

func Test_ListPermission_returns_401_if_non_user(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.get("/permissions")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_ListPermission_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 3)
	req, err := svr.getAs(u, "/permissions")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_ListPermission_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permissions")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
