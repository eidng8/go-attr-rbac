package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

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
			if "" == method { // process auth cookies
				if token, err = s.handleCookieAuth(gc); err != nil {
					gc.AbortWithStatus(http.StatusUnauthorized)
					return nil, err
				}
			} else { // process auth header
				if token, err = s.handleAuthHeader(method, st); err != nil {
					gc.AbortWithStatus(http.StatusUnauthorized)
					return nil, err
				}
			}
			gc.Set(AccessTokenName, token)
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
		return nil, ErrInvalidHeader
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
		return "", "", ErrInvalidHeader
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
