package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-ent/paginate"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

func Test_ListUserRoles_returns_1st_page(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	expected := ListUserRolesPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Role]{
			Total:        1,
			PerPage:      10,
			CurrentPage:  1,
			LastPage:     1,
			FirstPageUrl: svr.baseUrl + "/user/1/roles?page=1&per_page=10",
			LastPageUrl:  "",
			NextPageUrl:  "",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/user/1/roles",
			From:         1,
			To:           1,
			Data: db.Role.Query().Where(role.IDEQ(1)).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 1)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/user/1/roles")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListUserRoles_filters_by_name(t *testing.T) {
	svr, engine, db, res := setup(t, false)
	expected := ListUserRolesPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.Role]{
			Total:        1,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     1,
			FirstPageUrl: svr.baseUrl + "/user/2/roles?name=role+0&page=1&per_page=5",
			LastPageUrl:  "",
			NextPageUrl:  "",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/user/2/roles",
			From:         1,
			To:           1,
			Data: db.Role.Query().Where(role.NameEQ("role 0")).
				AllX(context.Background()),
		},
	}
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/user/2/roles?name=role+0&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListUserRoles_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setup(t, false)
	_, err := svr.ListUserRoles(
		context.Background(), ListUserRolesRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}
