package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func Test_ReadPersonalToken_returns_a_personal_token(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	uuid7, err := uuid.NewV7()
	require.Nil(t, err)
	b, err := uuid7.MarshalBinary()
	require.Nil(t, err)
	db.PersonalToken.Create().SetDescription("test").
		SetUserID(2).SetToken(b).SaveX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/personal-token/1")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := unmarshalResponse(t, ReadPersonalToken200JSONResponse{}, res)
	require.Equal(t, uint64(1), actual.Id)
	require.Equal(t, uint64(2), actual.UserId)
	require.Equal(t, "test", actual.Description)
}

func Test_ReadPersonalToken_returns_404_if_not_found(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/personal-token/12345")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func Test_ReadPersonalToken_returns_401_if_non_user(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.get("/personal-token/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_ReadPersonalToken_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 3)
	req, err := svr.getAs(u, "/personal-token/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_ReadPersonalToken_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.getAs(u, "/personal-token/1")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
