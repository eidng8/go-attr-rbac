package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent"
)

func Test_HintPermissions_returns_5_rows(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	svr.hintSize = 5
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/q/permissions?q=auth")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	permissions := unmarshalResponse(t, []ent.Permission{}, res)
	require.Len(t, permissions, 5)
}