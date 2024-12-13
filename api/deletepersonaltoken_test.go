package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
)

func Test_DeletePersonalToken_deletes_a_personal_token(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	jti, err := uuid.NewV7()
	require.Nil(t, err)
	b, err := jti.MarshalBinary()
	require.Nil(t, err)
	tk := db.PersonalToken.Create().SetDescription("test").SetUserID(1).
		SetToken(b).SaveX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, fmt.Sprintf("/personal-token/%d", tk.ID))
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	require.False(
		t,
		db.PersonalToken.Query().Where(personaltoken.IDEQ(tk.ID)).
			ExistX(context.Background()),
	)
}

func Test_DeletePersonalToken_returns_401_if_non_user(t *testing.T) {
	svr, engine, _, res := setupTestCase(t, false)
	req, err := svr.delete("/personal-token/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
}

func Test_DeletePersonalToken_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 2)
	req, err := svr.deleteAs(u, "/personal-token/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
}

func Test_DeletePersonalToken_reports_404_if_user_exists(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/personal-token/12345")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 404, res.Code)
}

func Test_DeletePersonalToken_reports_422_if_invalid_id(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/personal-token/a")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
}

func Test_DeletePersonalToken_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, fmt.Sprintf("/personal-token/1"))
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
