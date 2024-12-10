package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func requireJsonEqualsString(
	t *testing.T, expected interface{}, actual string,
) {
	exp, err := json.Marshal(expected)
	require.Nil(t, err)
	require.JSONEq(t, string(exp), actual)
}

func requireJsonEquals(t *testing.T, expected, actual interface{}) {
	act, err := json.Marshal(actual)
	require.Nil(t, err)
	requireJsonEqualsString(t, expected, string(act))
}
