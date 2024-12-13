package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-ent/paginate"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

func Test_ListRoleUsers_returns_1st_page(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListRoleUsersPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.User]{
			Total:        1,
			PerPage:      10,
			CurrentPage:  1,
			LastPage:     1,
			FirstPageUrl: svr.baseUrl + "/role/1/users?page=1&per_page=10",
			LastPageUrl:  "",
			NextPageUrl:  "",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/role/1/users",
			From:         1,
			To:           1,
			Data: db.User.Query().Where(user.IDEQ(1)).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 1)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/role/1/users")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListRoleUsers_filters_by_name(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	expected := ListRoleUsersPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.User]{
			Total:        0,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     1,
			FirstPageUrl: svr.baseUrl + "/role/1/users?name=user&page=1&per_page=5",
			LastPageUrl:  "",
			NextPageUrl:  "",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/role/1/users",
			From:         0,
			To:           0,
			Data:         make([]*ent.User, 0),
		},
	}
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/role/1/users?name=user&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListRoleUsers_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setupTestCase(t, false)
	_, err := svr.ListRoleUsers(
		context.Background(), ListRoleUsersRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}

func Test_ListRoleUsers_returns_401_if_non_user(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.get("/role/2/users")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_ListRoleUsers_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 3)
	req, err := svr.getAs(u, "/role/2/users")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_ListRoleUsers_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/role/1/users")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
