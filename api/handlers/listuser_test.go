package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-ent/paginate"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

func Test_ListUser_returns_10_per_page(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	expected := ListUserPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.User]{
			Total:        11,
			PerPage:      10,
			CurrentPage:  1,
			LastPage:     2,
			FirstPageUrl: svr.baseUrl + "/users?page=1&per_page=10",
			LastPageUrl:  svr.baseUrl + "/users?page=2&per_page=10",
			NextPageUrl:  svr.baseUrl + "/users?page=2&per_page=10",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/users",
			From:         1,
			To:           10,
			Data: db.User.Query().Order(user.ByID()).Limit(10).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 10)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/users")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListUser_returns_5_per_page(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	expected := ListUserPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.User]{
			Total:        11,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     3,
			FirstPageUrl: svr.baseUrl + "/users?page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/users?page=3&per_page=5",
			NextPageUrl:  svr.baseUrl + "/users?page=2&per_page=5",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/users",
			From:         1,
			To:           5,
			Data: db.User.Query().Order(user.ByID()).Limit(5).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/users?per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListUser_returns_2nd_page(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	expected := ListUserPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.User]{
			Total:        11,
			PerPage:      5,
			CurrentPage:  2,
			LastPage:     3,
			FirstPageUrl: svr.baseUrl + "/users?page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/users?page=3&per_page=5",
			NextPageUrl:  svr.baseUrl + "/users?page=3&per_page=5",
			PrevPageUrl:  svr.baseUrl + "/users?page=1&per_page=5",
			Path:         svr.baseUrl + "/users",
			From:         6,
			To:           10,
			Data: db.User.Query().Order(user.ByID()).Limit(5).Offset(5).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/users?page=2&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListUser_filters_by_username(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	expected := ListUserPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.User]{
			Total:        10,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     2,
			FirstPageUrl: svr.baseUrl + "/users?name=user&page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/users?name=user&page=2&per_page=5",
			NextPageUrl:  svr.baseUrl + "/users?name=user&page=2&per_page=5",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/users",
			From:         1,
			To:           5,
			Data: db.User.Query().Order(user.ByID()).Limit(5).
				Where(user.UsernameHasPrefix("user")).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/users?name=user&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListUser_filters_by_email(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	expected := ListUserPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.User]{
			Total:        10,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     2,
			FirstPageUrl: svr.baseUrl + "/users?name=email&page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/users?name=email&page=2&per_page=5",
			NextPageUrl:  svr.baseUrl + "/users?name=email&page=2&per_page=5",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/users",
			From:         1,
			To:           5,
			Data: db.User.Query().Order(user.ByID()).Limit(5).
				Where(user.UsernameHasPrefix("user")).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/users?name=email&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListUser_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setup(t, false)
	_, err := svr.ListUser(context.Background(), ListUserRequestObject{})
	require.ErrorIs(t, err, errInvalidContext)
}
