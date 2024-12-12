package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-ent/paginate"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
)

func Test_ListPersonalToken_returns_10_per_page(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	seedPersonalTokens(t, db, 1)
	expected := ListPersonalTokenPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.PersonalToken]{
			Total:        10,
			PerPage:      10,
			CurrentPage:  1,
			LastPage:     1,
			FirstPageUrl: svr.baseUrl + "/personal-tokens?page=1&per_page=10",
			LastPageUrl:  "",
			NextPageUrl:  "",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/personal-tokens",
			From:         1,
			To:           10,
			Data: db.PersonalToken.Query().Order(personaltoken.ByID()).Limit(10).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 10)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/personal-tokens")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListPersonalToken_returns_5_per_page(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	seedPersonalTokens(t, db, 1)
	expected := ListPersonalTokenPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.PersonalToken]{
			Total:        10,
			PerPage:      5,
			CurrentPage:  1,
			LastPage:     2,
			FirstPageUrl: svr.baseUrl + "/personal-tokens?page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/personal-tokens?page=2&per_page=5",
			NextPageUrl:  svr.baseUrl + "/personal-tokens?page=2&per_page=5",
			PrevPageUrl:  "",
			Path:         svr.baseUrl + "/personal-tokens",
			From:         1,
			To:           5,
			Data: db.PersonalToken.Query().Order(personaltoken.ByID()).Limit(5).
				AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/personal-tokens?per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListPersonalToken_returns_2nd_page(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	seedPersonalTokens(t, db, 1)
	expected := ListPersonalTokenPaginateResponse{
		PaginatedList: &paginate.PaginatedList[ent.PersonalToken]{
			Total:        10,
			PerPage:      5,
			CurrentPage:  2,
			LastPage:     2,
			FirstPageUrl: svr.baseUrl + "/personal-tokens?page=1&per_page=5",
			LastPageUrl:  svr.baseUrl + "/personal-tokens?page=2&per_page=5",
			NextPageUrl:  "",
			PrevPageUrl:  svr.baseUrl + "/personal-tokens?page=1&per_page=5",
			Path:         svr.baseUrl + "/personal-tokens",
			From:         6,
			To:           10,
			Data: db.PersonalToken.Query().Order(personaltoken.ByID()).Limit(5).
				Offset(5).AllX(context.Background()),
		},
	}
	require.Len(t, expected.PaginatedList.Data, 5)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/personal-tokens?page=2&per_page=5")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	requireJsonEqualsString(t, expected, res.Body.String())
}

func Test_ListPersonalToken_returns_500_if_invalid_context(t *testing.T) {
	svr, _, _, _ := setup(t, false)
	_, err := svr.ListPersonalToken(
		context.Background(), ListPersonalTokenRequestObject{},
	)
	require.ErrorIs(t, err, errInvalidContext)
}
