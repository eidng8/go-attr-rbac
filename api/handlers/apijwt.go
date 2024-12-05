package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/eidng8/go-utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/accesstoken"
	"github.com/eidng8/go-attr-rbac/ent/permission"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

func (s Server) issueAccessToken(user *ent.User) (string, error) {
	roles, err := user.QueryRoles().Select("name").All(context.Background())
	if err != nil {
		return "", err
	}
	r := utils.Pluck(roles, func(r *ent.Role) string { return r.Name })
	return s.issueJwtToken(user, time.Hour, &r)
}

func (s Server) issueRefreshToken(user *ent.User) (string, error) {
	return s.issueJwtToken(user, 7*24*time.Hour, nil)
}

func (s Server) issuePersonalToken(user *ent.User, scopes string) (
	string, error,
) {
	return s.issueJwtToken(user, 7*24*time.Hour, nil)
}

// issueAccessToken issues an access token for the user.
// Doesn't access database.
func (s Server) issueJwtToken(
	user *ent.User, ttl time.Duration, roles *[]string,
) (string, error) {
	var attr *map[string]interface{}
	uid, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	if roles != nil {
		attr = user.Attr
	}
	claims := jwt.NewWithClaims(
		jwt.SigningMethodHS256, accessTokenClaims{
			Roles: roles,
			Attr:  attr,
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        uid.String(),
				Audience:  []string{s.Domain()}, // TODO allow customize?
				Issuer:    s.Domain(),           // TODO allow customize?
				Subject:   fmt.Sprintf("%d", user.ID),
				IssuedAt:  &jwt.NumericDate{Time: time.Now()},
				ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(ttl)},
			},
		},
	)
	claims.Method = jwt.SigningMethodHS256
	token, err := claims.SignedString(s.secret)
	if err != nil {
		return "", err
	}
	return token, nil
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
	s.setCookie(gc, accessTokenName, "", "/", -1)
	s.setCookie(gc, refreshTokenName, "", api.RefreshTokenPath, -1)
	return err
}

// Checks whether the given user has permission to perform the given operation.
// TODO add role permission caching
func (s Server) operationAllowed(user *ent.User, operation string) error {
	if nil == user.Edges.Roles {
		err := loadRoles(user)
		if err != nil {
			return err
		}
	}
	if len(user.Edges.Roles) == 0 {
		return errAccessDenied
	}
	a := utils.Pluck(user.Edges.Roles, func(r *ent.Role) uint32 { return r.ID })
	found, err := s.db.Role.Query().Where(role.IDIn(a...)).QueryPermissions().
		Where(permission.NameEQ("auth:" + operation)).
		Exist(context.Background())
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	return errAccessDenied
}
