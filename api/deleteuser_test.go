package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/eidng8/go-ent/softdelete"
	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/ent/user"
)

func Test_DeleteUser_soft_deletes_a_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/user/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	require.False(
		t, db.User.Query().Where(user.IDEQ(2)).ExistX(context.Background()),
	)
	tt := true
	require.True(
		t, db.User.Query().Where(user.IDEQ(2)).ExistX(
			softdelete.NewSoftDeleteQueryContext(
				&tt, context.Background(),
			),
		),
	)
}

func Test_DeleteUser_physically_deletes_a_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, true)
	db.User.DeleteOneID(2).ExecX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/user/2?trashed=1")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
	tt := true
	require.False(
		t, db.User.Query().Where(user.IDEQ(2)).ExistX(
			softdelete.NewSoftDeleteQueryContext(
				&tt, context.Background(),
			),
		),
	)
}

func Test_DeleteUser_returns_401_if_non_user(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	req, err := svr.delete("/user/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.True(
		t, db.User.Query().Where(user.IDEQ(2)).ExistX(context.Background()),
	)
}

func Test_DeleteUser_returns_403_if_user_without_permission(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 2)
	req, err := svr.deleteAs(u, "/user/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.True(
		t, db.User.Query().Where(user.IDEQ(2)).ExistX(context.Background()),
	)
}

func Test_DeleteUser_reports_404_if_user_not_exists(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/user/12345")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 404, res.Code)
}

func Test_DeleteUser_reports_404_if_user_was_soft_deleted(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	db.User.DeleteOneID(2).ExecX(context.Background())
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/user/2")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func Test_DeleteUser_reports_422_if_invalid_id(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/user/a")
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, 422, res.Code)
}

func Test_DeleteUser_returns_500_if_db_error_unhandled(t *testing.T) {
	svr, engine, db, res := setupTestCase(t, false)
	u := getUserById(t, db, 1)
	req, err := svr.deleteAs(u, "/user/2")
	require.Nil(t, err)
	svr.db = useEmptyDb(t)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusInternalServerError, res.Code)
}
