package handlers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eidng8/go-attr-rbac/api"
)

func Test_getHintSize_handles_invalid_hint_size(t *testing.T) {
	require.Nil(t, os.Setenv(api.HintSizeName, "0"))
	require.Equal(t, 5, getHintSize(5))
}

func Test_getSecret_returns_error_if_secret_empty(t *testing.T) {
	require.Nil(t, os.Setenv(api.PrivateKeyName, ""))
	_, err := getSecret()
	require.NotNil(t, err)
}

func Test_getSecret_returns_error_if_secret_invalid(t *testing.T) {
	require.Nil(t, os.Setenv(api.PrivateKeyName, "*/-+"))
	_, err := getSecret()
	require.NotNil(t, err)
}
