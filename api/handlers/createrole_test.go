package handlers

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_CreateRole_creates_role(t *testing.T) {
	desc := "test descriptions"
	body := CreateRoleJSONBody{Name: "test_role", Description: &desc}
	jo, err := json.Marshal(body)
	require.Nil(t, err)
	_, engine, _, res := setup(t, false)
	req, err := http.NewRequest(
		http.MethodPost, "/roles", io.NopCloser(strings.NewReader(string(jo))),
	)
	require.Nil(t, err)
	engine.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	actual := Role{}
	require.Nil(t, json.Unmarshal([]byte(res.Body.String()), &actual))
	require.Equal(t, body.Name, actual.Name)
	require.Equal(t, body.Description, actual.Description)
	require.Greater(t, actual.Id, 10)
}
