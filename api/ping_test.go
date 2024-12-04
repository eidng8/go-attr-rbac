package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Ping(t *testing.T) {
	require.Nil(t, os.Setenv(PublicOpsName, "ping"))
	require.Nil(t, os.Setenv(PrivateKeyName, buildSecret(32)))
	_, engine, err := NewEngine(nil)
	require.Nil(t, err)
	res := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/ping", nil)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)
}
