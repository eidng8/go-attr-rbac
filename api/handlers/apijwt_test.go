package handlers

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func Test_issueAccessToken(t *testing.T) {
	var actual any
	server, _, db, _ := setup(t, true)
	u := getUserById(t, db, 1)
	accessToken, err := server.issueAccessToken(u)
	require.Nil(t, err)
	at, err := server.jwtTokenFromString(accessToken)
	require.Nil(t, err)
	require.Equal(t, server, at.svr)
	require.Nil(t, at.getUserBySubject())
	require.Equal(t, u.ID, at.user.ID)
	actual, err = at.token.Claims.GetAudience()
	require.Nil(t, err)
	require.Equal(t, jwt.ClaimStrings{"localhost"}, actual)
	actual, err = at.token.Claims.GetIssuer()
	require.Nil(t, err)
	require.Equal(t, "localhost", actual)
	actual, err = at.token.Claims.GetIssuedAt()
	require.Nil(t, err)
	require.True(t, actual.(*jwt.NumericDate).Before(time.Now()), actual)
	actual, err = at.getRoles()
	require.Nil(t, err)
	require.Equal(t, &[]string{"root"}, actual)
	actual, err = at.getAttr()
	require.Nil(t, err)
	require.Equal(
		t, &map[string]interface{}{"dept": int64(1), "level": int64(1)}, actual,
	)
}

func Test_issueRefreshToken(t *testing.T) {
	var actual any
	server, _, db, _ := setup(t, true)
	u := getUserById(t, db, 1)
	refreshToken, err := server.issueRefreshToken(u)
	require.Nil(t, err)
	rt, err := server.jwtTokenFromString(refreshToken)
	require.Nil(t, err)
	require.Equal(t, server, rt.svr)
	require.Nil(t, rt.getUserBySubject())
	require.Equal(t, u.ID, rt.user.ID)
	actual, err = rt.token.Claims.GetAudience()
	require.Nil(t, err)
	require.Equal(t, jwt.ClaimStrings{"localhost"}, actual)
	actual, err = rt.token.Claims.GetIssuer()
	require.Nil(t, err)
	require.Equal(t, "localhost", actual)
	actual, err = rt.token.Claims.GetIssuedAt()
	require.Nil(t, err)
	require.True(t, actual.(*jwt.NumericDate).Before(time.Now()), actual)
	actual, err = rt.getRoles()
	require.True(t, errors.Is(err, errInvalidToken))
	require.Nil(t, actual)
	actual, err = rt.getAttr()
	require.True(t, errors.Is(err, errInvalidToken))
	require.Nil(t, actual)
}
