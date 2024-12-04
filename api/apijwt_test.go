package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_issueAccessToken(t *testing.T) {
	server, _, db, _ := setup(t)
	u := getUserById(t, db, 1)
	accessToken, err := server.issueAccessToken(u)
	require.Nil(t, err)
	jwt, err := server.jwtTokenFromString(accessToken)
	require.Nil(t, err)
	require.Equal(t, server, jwt.svr)
	require.Nil(t, jwt.getUserBySubject())
	require.Equal(t, u.ID, jwt.user.ID)
}

func Test_issueRefreshToken(t *testing.T) {
	server, _, db, _ := setup(t)
	u := getUserById(t, db, 1)
	refreshToken, err := server.issueRefreshToken(u)
	require.Nil(t, err)
	jwt, err := server.jwtTokenFromString(refreshToken)
	require.Nil(t, err)
	require.Equal(t, server, jwt.svr)
	require.Nil(t, jwt.getUserBySubject())
	require.Equal(t, u.ID, jwt.user.ID)
}
