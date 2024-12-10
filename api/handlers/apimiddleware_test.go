package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// this test is here for future change on auth & validation middleware, if it
// were to be made.
//
// In current setup, validation middleware is registered with `gin.use()`,
// which is a router group middleware. While auth middleware is registered
// using NewStrictHandler, which is an operation (route) middleware.
// `gin.combineHandlers()` puts all router group middleware before operation
// middleware. This means that the request will be validated before it is
// authenticated. This test is here to ensure that this behavior will not go
// un-noticed if this behavior were changed.
func Test_authMiddleware_runs_after_request_validation(t *testing.T) {
	svr, engine, _, res := setup(t, false)
	req, err := svr.post("/role/3/permissions", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnprocessableEntity, res.Code)
}
