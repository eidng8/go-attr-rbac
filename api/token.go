package api

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/accesstoken"
	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

const (
	AccessTokenName  = "access_token"
	RefreshTokenName = "refresh_token"
)

var (
	ErrInvalidToken = errors.New("invalid_token")
	ErrEmptyToken   = errors.New("empty_token")
)

type jwtToken struct {
	svr   *Server
	token *jwt.Token
	user  *ent.User
}

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Roles      *[]string   `json:"roles,omitempty"`
	Attributes interface{} `json:"attributes,omitempty"`
}

type PersonalTokenClaims struct {
	jwt.RegisteredClaims
	Scopes string `json:"scopes,omitempty"`
}

// getJti returns the token's uuid from JTI.
// Doesn't access database. Doesn't log errors.
func (tk *jwtToken) getJti() (uuid.UUID, error) {
	claims, ok := tk.token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, ErrInvalidToken
	}
	jti, ok := claims["jti"].(string)
	if !ok {
		return uuid.Nil, ErrInvalidToken
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
	if err != nil {
		Log.Debugf("failed to get subject from token: %v", err)
		return ErrInvalidToken
	}
	id, err := strconv.ParseUint(subject, 10, 64)
	if err != nil {
		Log.Debugf("invalid subject %s", subject)
		return ErrInvalidToken
	}
	u, err := tk.svr.db.User.Query().Where(user.IDEQ(id)).
		First(context.Background())
	if err != nil {
		Log.Debugf("query user error: %s", err)
		return ErrInvalidToken
	}
	if nil == u {
		Log.Debugf("user not found %d", id)
		return ErrInvalidToken
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
		return ErrInvalidToken
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
				Log.Debugf("access token jti query error: %v", err)
				return false
			}
			// access token uses black list
			return !exist
		},
	)
	if err != nil {
		Log.Debugf("access token error: %v", err)
		return ErrInvalidToken
	}
	if !valid {
		Log.Debugf("access token invalid")
		return ErrInvalidToken
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
				Log.Debugf("refresh token jti query error: %v", err)
				return false
			}
			// refresh token uses black list
			return !exist
		},
	)
	if err != nil {
		Log.Debugf("refresh token error: %v", err)
		return ErrInvalidToken
	}
	if !valid {
		Log.Debugf("refresh token invalid")
		return ErrInvalidToken
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
				Log.Debugf("personal token jti query error: %v", err)
				return false
			}
			// personal token uses white list
			return exist
		},
	)
	if err != nil {
		Log.Debugf("personal token error: %v", err)
		return ErrInvalidToken
	}
	if !valid {
		Log.Debugf("personal token invalid")
		return ErrInvalidToken
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
		Log.Debugf("invalid jti: %v", err)
		return false, ErrInvalidToken
	}
	if !valid(jti) {
		return false, ErrInvalidToken
	}
	if err = tk.getUserBySubject(); err != nil {
		return true, ErrInvalidToken
	}
	return true, nil
}

// expired checks if the token is expired. Doesn't access database.
// Debug logs errors.
func (tk *jwtToken) expired() error {
	exp, err := tk.token.Claims.GetExpirationTime()
	if err != nil {
		Log.Debugf("invalid expiration %v", err)
		return ErrInvalidToken
	}
	if exp.IsZero() {
		Log.Debugf("zero expiration")
		return ErrInvalidToken
	}
	if exp.Before(time.Now()) {
		Log.Debugf(jwt.ErrTokenExpired.Error())
		return jwt.ErrTokenExpired
	}
	return nil
}
