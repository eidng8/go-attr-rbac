package handlers

import (
	"context"
	jso "encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/eidng8/go-utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/accesstoken"
	"github.com/eidng8/go-attr-rbac/ent/personaltoken"
	"github.com/eidng8/go-attr-rbac/ent/user"
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

// Returns the roles from the JWT token. It does NOT access the database, just
// reads roles from the token's claims. To actually get roles from database,
// use the user field directly.
func (tk *jwtToken) getRoles() (*[]string, error) {
	claims, ok := tk.token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errInvalidToken
	}
	is, ok := claims["roles"].([]interface{})
	if !ok {
		return nil, errInvalidToken
	}
	roles, err := utils.SliceMapFunc(is, utils.MapToType[string])
	if err != nil {
		return nil, err
	}
	return &roles, nil
}

func (tk *jwtToken) getScopes() (*[]string, error) {
	claims, ok := tk.token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errInvalidToken
	}
	is, ok := claims["scopes"].([]interface{})
	if !ok {
		return nil, errInvalidToken
	}
	scopes, err := utils.SliceMapFunc(is, utils.MapToType[string])
	if err != nil {
		return nil, err
	}
	return &scopes, nil
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

// Returns the token's uuid from JTI.
// Doesn't access database. Doesn't log errors.
func (tk *jwtToken) getJti() (*uuid.UUID, error) {
	claims, ok := tk.token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errInvalidToken
	}
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, errInvalidToken
	}
	id, err := uuid.Parse(jti)
	if err != nil {
		return nil, err
	}
	return &id, nil
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
	// TODO enhance the key func
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

// Issues an access token for the user. Doesn't access database.
func (s Server) issueAccessToken(user *ent.User) (string, error) {
	return s.issueJwtToken(user, time.Hour)
}

// Issues a refresh token for the user. Doesn't access database.
func (s Server) issueRefreshToken(user *ent.User) (string, error) {
	return s.issueJwtToken(user, 7*24*time.Hour)
}

// Issues a personal token for the user. Doesn't access database.
func (s Server) issuePersonalToken(
	user *ent.User, scopes []string, ttl time.Duration,
) (*uuid.UUID, string, error) {
	uid, claims, err := s.buildTokenClaims(user, ttl)
	if err != nil {
		return nil, "", err
	}
	claims.Scopes = &scopes
	token, err := s.issueJwtTokenWithClaims(jwt.SigningMethodHS256, claims)
	if err != nil {
		return nil, "", err
	}
	return uid, token, nil
}

// issueAccessToken issues an access token for the user.
// Doesn't access database.
func (s Server) issueJwtToken(user *ent.User, ttl time.Duration) (
	string, error,
) {
	_, claims, err := s.buildTokenClaims(user, ttl)
	if err != nil {
		return "", err
	}
	return s.issueJwtTokenWithClaims(jwt.SigningMethodHS256, claims)
}

// Issues a JWT token with the given claims. Doesn't access database.
func (s Server) issueJwtTokenWithClaims(
	method jwt.SigningMethod, claims *accessTokenClaims,
) (string, error) {
	t := jwt.NewWithClaims(method, claims)
	ts, err := t.SignedString(s.secret)
	if err != nil {
		return "", err
	}
	return ts, nil
}

// Builds the token claims for the user. Doesn't access database.
func (s Server) buildTokenClaims(user *ent.User, ttl time.Duration) (
	*uuid.UUID, *accessTokenClaims, error,
) {
	if user == nil {
		return nil, nil, errInvalidArgument
	}
	var roles *[]string = nil
	var attr *map[string]interface{} = nil
	uid, err := uuid.NewV7()
	if err != nil {
		return nil, nil, err
	}
	if user.Edges.Roles != nil {
		attr = user.Attr
		r := utils.Pluck(
			user.Edges.Roles, func(r *ent.Role) string { return r.Name },
		)
		roles = &r
	}
	return &uid, &accessTokenClaims{
		Roles: roles,
		Attr:  attr,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uid.String(),
			Audience:  []string{s.Domain()}, // TODO allow customize?
			Issuer:    s.Domain(),           // TODO allow customize?
			Subject:   fmt.Sprintf("%d", user.ID),
			IssuedAt:  &jwt.NumericDate{Time: time.Now()},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(ttl * time.Second)},
		},
	}, nil
}

func (s Server) jwtTokenFromString(token string) (*jwtToken, error) {
	t := jwtToken{svr: &s}
	if err := t.parse(token); err != nil {
		return nil, err
	}
	return &t, nil
}

// jwtTokenFromCookie gets token from the cookie. Doesn't access database.
// Debug logs errors.
func (s Server) jwtTokenFromCookie(gc *gin.Context, name string) (
	*jwtToken, error,
) {
	cookie, err := gc.Cookie(name)
	if err != nil {
		api.Log.Debugf("failed to get access token: %v", err)
		return nil, err
	}
	if "" == cookie {
		api.Log.Debugf("failed to get access token: empty cookie")
		return nil, errEmptyToken
	}
	token, err := s.jwtTokenFromString(cookie)
	if err != nil {
		api.Log.Debugf("parse token error: %v", err)
		return nil, errInvalidToken
	}
	if err = token.expired(); err != nil {
		return nil, err
	}
	return token, nil
}

// getAccessToken verifies the access token from cookie and returns it if valid.
// Accesses database. Debug logs errors.
func (s Server) getAccessToken(gc *gin.Context) (*jwtToken, error) {
	token, err := s.jwtTokenFromCookie(gc, accessTokenName)
	if err != nil {
		return nil, err
	}
	if err = token.checkAccessToken(); err != nil {
		return nil, err
	}
	return token, nil
}

// getRefreshToken verifies the refresh token from cookie, returns it if valid.
// Accesses database. Debug logs errors.
func (s Server) getRefreshToken(gc *gin.Context) (*jwtToken, error) {
	token, err := s.jwtTokenFromCookie(gc, refreshTokenName)
	if err != nil {
		return nil, err
	}
	if err = token.checkRefreshToken(); err != nil {
		return nil, err
	}
	return token, nil
}

func (s Server) revokeAccessToken(ctx context.Context) error {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return errInvalidContext
	}
	at, ok := gc.Value(accessTokenName).(*jwtToken)
	if !ok {
		return errInvalidToken
	}
	// check if the token jti was revoked
	atid, err := at.getJtiBinary()
	if err != nil {
		api.Log.Debugf("invalid acess token id %v", at)
		return errInvalidToken
	}
	rt, err := s.getRefreshToken(gc)
	if err != nil {
		api.Log.Debugf("invalid refresh token: %v", err)
		return errInvalidToken
	}
	rtid, err := rt.getJtiBinary()
	if err != nil {
		api.Log.Debugf("invalid refresh token id %v", rt)
		return errInvalidToken
	}
	exist, err := s.db.AccessToken.Query().Where(
		accesstoken.Or(
			accesstoken.AccessTokenEQ(atid), accesstoken.RefreshTokenEQ(rtid),
		),
	).Exist(context.Background())
	if err != nil {
		api.Log.Debugf("token query error: %v", err)
		return err
	}
	if exist {
		api.Log.Debugf("access token or refresh token has been revoked")
		return errInvalidToken
	}
	// add the token to the revoked list
	_, err = s.db.Transaction(
		context.Background(),
		func(ctx context.Context, tx *ent.Tx) (interface{}, error) {
			_, err := tx.AccessToken.Create().SetUserID(at.user.ID).
				SetAccessToken(atid).SetRefreshToken(rtid).
				Save(ctx)
			if err != nil {
				return nil, err
			}
			return nil, nil
		},
	)
	gc.SetSameSite(http.SameSiteStrictMode)
	s.setCookie(gc, accessTokenName, "", api.AccessTokenPath, -1)
	s.setCookie(gc, refreshTokenName, "", api.RefreshTokenPath, -1)
	return err
}
