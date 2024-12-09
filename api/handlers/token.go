package handlers

import (
	"context"
	jso "encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/accesstoken"
	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

const (
	accessTokenName  = "access_token"
	refreshTokenName = "refresh_token"
)

var (
	errInvalidArgument = errors.New("invalid_argument")
	errInvalidToken    = errors.New("invalid_token")
	errEmptyToken      = errors.New("empty_token")
	errInvalidContext  = errors.New("invalid_context")
	errInvalidHeader   = errors.New("invalid_header")
	errAccessDenied    = errors.New("access_denied")
)

type jwtToken struct {
	svr   *Server
	token *jwt.Token
	user  *ent.User
}

type accessTokenClaims struct {
	jwt.RegisteredClaims
	Roles  *[]string               `json:"roles,omitempty"`
	Attr   *map[string]interface{} `json:"attr,omitempty"`
	Scopes *[]string               `json:"scopes,omitempty"`
}

func (tk *jwtToken) getRoles() (*[]string, error) {
	claims, ok := tk.token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errInvalidToken
	}
	is, ok := claims["roles"].([]interface{})
	if !ok {
		return nil, errInvalidToken
	}
	roles := make([]string, len(is))
	for i, r := range is {
		roles[i], ok = r.(string)
		if !ok {
			return nil, errInvalidToken
		}
	}
	return &roles, nil
}

func (tk *jwtToken) getAttr() (*map[string]interface{}, error) {
	claims, ok := tk.token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errInvalidToken
	}
	is, ok := claims["attr"].(map[string]interface{})
	if !ok {
		return nil, errInvalidToken
	}
	attr := make(map[string]interface{}, len(is))
	for k, v := range is {
		av, ok := v.(jso.Number)
		if !ok {
			return nil, errInvalidToken
		}
		n, err := av.Int64()
		if err != nil {
			return nil, err
		}
		attr[k] = n
	}
	return &attr, nil
}

// getJti returns the token's uuid from JTI.
// Doesn't access database. Doesn't log errors.
func (tk *jwtToken) getJti() (uuid.UUID, error) {
	claims, ok := tk.token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, errInvalidToken
	}
	jti, ok := claims["jti"].(string)
	if !ok {
		return uuid.Nil, errInvalidToken
	}
	id, err := uuid.Parse(jti)
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// getJtiBinary returns the token's uuid from JTI, as binary.
// Doesn't access database. Doesn't log errors.
func (tk *jwtToken) getJtiBinary() ([]byte, error) {
	id, err := tk.getJti()
	if err != nil {
		return nil, err
	}
	bytes, err := id.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// getUserBySubject checks the subject validity and retrieves the user.
// Accesses database. Debug logs errors.
func (tk *jwtToken) getUserBySubject() error {
	subject, err := tk.token.Claims.GetSubject()
	if err != nil || "" == subject {
		api.Log.Debugf("failed to get subject from token: %v", err)
		return errInvalidToken
	}
	id, err := strconv.ParseUint(subject, 10, 64)
	if err != nil {
		api.Log.Debugf("invalid subject %s", subject)
		return errInvalidToken
	}
	u, err := tk.svr.db.User.Query().WithRoles().Where(user.IDEQ(id)).
		First(context.Background())
	if err != nil {
		api.Log.Debugf("query user error: %s", err)
		return errInvalidToken
	}
	if nil == u {
		api.Log.Debugf("user not found %d", id)
		return errInvalidToken
	}
	tk.user = u
	return nil
}

// parse parses the token string and verify its basic validity:
// * must use HS256 algorithm;
// * must have exp claim;
// * must aud claim match the server domain;
// * must iss claim match the server domain.
// Doesn't access database. Doesn't log errors.
func (tk *jwtToken) parse(token string) error {
	t, err := jwt.Parse(
		token, tk.svr.getSecret, jwt.WithJSONNumber(),
		jwt.WithExpirationRequired(), jwt.WithIssuer(tk.svr.Domain()),
		jwt.WithAudience(tk.svr.Domain()), jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)
	if err != nil {
		return err
	}
	if !t.Valid {
		return errInvalidToken
	}
	tk.token = t
	return nil
}

// checkAccessToken checks the access token validity.
// Accesses database. Debug logs errors.
func (tk *jwtToken) checkAccessToken() error {
	valid, err := tk.checkToken(
		func(jti []byte) bool {
			exist, err := tk.svr.db.AccessToken.Query().
				Where(accesstoken.AccessTokenEQ(jti)).
				Exist(context.Background())
			if err != nil {
				api.Log.Debugf("access token jti query error: %v", err)
				return false
			}
			// access token uses black list
			return !exist
		},
	)
	if err != nil {
		api.Log.Debugf("access token error: %v", err)
		return errInvalidToken
	}
	if !valid {
		api.Log.Debugf("access token invalid")
		return errInvalidToken
	}
	return nil
}

// checkRefreshToken checks the refresh token validity.
// Accesses database. Debug logs errors.
func (tk *jwtToken) checkRefreshToken() error {
	valid, err := tk.checkToken(
		func(jti []byte) bool {
			exist, err := tk.svr.db.AccessToken.Query().
				Where(accesstoken.RefreshTokenEQ(jti)).
				Exist(context.Background())
			if err != nil {
				api.Log.Debugf("refresh token jti query error: %v", err)
				return false
			}
			// refresh token uses black list
			return !exist
		},
	)
	if err != nil {
		api.Log.Debugf("refresh token error: %v", err)
		return errInvalidToken
	}
	if !valid {
		api.Log.Debugf("refresh token invalid")
		return errInvalidToken
	}
	return nil
}

// checkPersonalToken checks the personal token validity.
// Accesses database. Debug logs errors.
func (tk *jwtToken) checkPersonalToken() error {
	valid, err := tk.checkToken(
		func(jti []byte) bool {
			exist, err := tk.svr.db.PersonalToken.Query().
				Where(personaltoken.TokenEQ(jti)).Exist(context.Background())
			if err != nil {
				api.Log.Debugf("personal token jti query error: %v", err)
				return false
			}
			// personal token uses white list
			return exist
		},
	)
	if err != nil {
		api.Log.Debugf("personal token error: %v", err)
		return errInvalidToken
	}
	if !valid {
		api.Log.Debugf("personal token invalid")
		return errInvalidToken
	}
	return nil
}

// checkToken checks JTI & SUB:
// returns true if the token pass the `valid()` check, otherwise false;
// also calls getUserBySubject() if the token is valid.
// Accesses database. Debug logs errors.
func (tk *jwtToken) checkToken(valid func([]byte) bool) (bool, error) {
	jti, err := tk.getJtiBinary()
	if err != nil {
		api.Log.Debugf("invalid jti: %v", err)
		return false, errInvalidToken
	}
	if !valid(jti) {
		return false, errInvalidToken
	}
	if err = tk.getUserBySubject(); err != nil {
		return true, errInvalidToken
	}
	return true, nil
}

// expired checks if the token is expired. Doesn't access database.
// Debug logs errors.
func (tk *jwtToken) expired() error {
	exp, err := tk.token.Claims.GetExpirationTime()
	if err != nil {
		api.Log.Debugf("invalid expiration %v", err)
		return errInvalidToken
	}
	if exp.IsZero() {
		api.Log.Debugf("zero expiration")
		return errInvalidToken
	}
	if exp.Before(time.Now()) {
		api.Log.Debugf(jwt.ErrTokenExpired.Error())
		return jwt.ErrTokenExpired
	}
	return nil
}
