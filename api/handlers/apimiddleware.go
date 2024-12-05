package handlers

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/role"
)

// authMiddleware authorizes the request and stores token's user with roles to
// gin context value accessTokenName.
func (s Server) authMiddleware() StrictMiddlewareFunc {
	return func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
		return func(gc *gin.Context, request interface{}) (interface{}, error) {
			if slices.Contains(s.publicOperations, operationID) {
				// pass-through public paths
				return f(gc, request)
			}
			var err error
			var token *jwtToken
			method, st, err := authHeader(gc)
			if err != nil {
				gc.AbortWithStatus(http.StatusUnauthorized)
				return nil, err
			}
			if "" == method {
				if token, err = s.handleCookieAuth(gc); err != nil {
					gc.AbortWithStatus(http.StatusUnauthorized)
					return nil, err
				}
			} else {
				if token, err = s.handleAuthHeader(method, st); err != nil {
					gc.AbortWithStatus(http.StatusUnauthorized)
					return nil, err
				}
			}
			if err = loadRoles(token.user); err != nil {
				gc.AbortWithStatus(http.StatusForbidden)
				return nil, err
			}
			if err = s.operationAllowed(token.user, operationID); err != nil {
				gc.AbortWithStatus(http.StatusForbidden)
				return nil, err
			}
			gc.Set(accessTokenName, token)
			return f(gc, request)
		}
	}
}

func (s Server) handleAuthHeader(method, token string) (t *jwtToken, e error) {
	switch strings.ToLower(method) {
	case "bearer": // process access token
		if t, e = s.handleBearerAuth(token); e != nil {
			return nil, e
		}
	case "token": // process personal (long-lived) token
		if t, e = s.handleTokenAuth(token); e != nil {
			return nil, e
		}
	default:
		return nil, errInvalidHeader
	}
	return
}

func (s Server) handleCookieAuth(gc *gin.Context) (*jwtToken, error) {
	token, err := s.getAccessToken(gc)
	if err != nil {
		return nil, err
	}
	return token, err
}

func (s Server) handleBearerAuth(token string) (*jwtToken, error) {
	t, err := s.jwtTokenFromString(token)
	if err != nil {
		return nil, err
	}
	err = t.checkAccessToken()
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s Server) handleTokenAuth(token string) (*jwtToken, error) {
	t, err := s.jwtTokenFromString(token)
	if err != nil {
		return nil, err
	}
	err = t.checkPersonalToken()
	if err != nil {
		return nil, err
	}
	return t, nil
}

func authHeader(gc *gin.Context) (string, string, error) {
	header := gc.GetHeader("Authorization")
	if "" == header {
		return "", "", nil
	}
	parts := strings.Split(header, " ")
	if len(parts) != 2 { // invalid header
		return "", "", errInvalidHeader
	}
	method, token := "", ""
	switch strings.ToLower(parts[0]) {
	case "bearer":
		method = "bearer"
		token = parts[1]
	case "token":
		method = "token"
		token = parts[1]
	}
	return method, token, nil
}

// Loads roles for the user and stores them in `Edges.Roles`.
// TODO add user role caching
func loadRoles(u *ent.User) error {
	roles, err := u.QueryRoles().Select(role.FieldID, role.FieldName).
		All(context.Background())
	if err != nil {
		return err
	}
	u.Edges.Roles = roles
	return nil
}
