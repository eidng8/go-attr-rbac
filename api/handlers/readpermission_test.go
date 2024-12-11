package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ReadPermission_returns_a_permission(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permission/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, ReadPermission200JSONResponse{}, res)
	require.Equal(t, uint32(2), actual.Id)
	require.Equal(t, "auth:CheckAccessToken", actual.Name)
}

func Test_ReadPermission_returns_404_if_not_found(t *testing.T) {
	svr, engine, db, res := setup(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/permission/12345")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}
