package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
)

func Test_HintUsers_returns_5_rows(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	svr.hintSize = 5
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/q/users?q=u")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	users := unmarshalResponse(t, []ent.User{}, res)
	require.Len(t, users, 5)
}

func Test_HintUsers_searches_by_email(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	svr.hintSize = 5
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/q/users?q=email")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	users := unmarshalResponse(t, []ent.User{}, res)
	require.Len(t, users, 5)
}
