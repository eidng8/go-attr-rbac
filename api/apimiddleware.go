package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	strictgin "github.com/oapi-codegen/runtime/strictmiddleware/gin"
)

func (s Server) authMiddleware() StrictMiddlewareFunc {
	return func(
		f strictgin.StrictGinHandlerFunc, operationID string,
	) strictgin.StrictGinHandlerFunc {
		return func(gc *gin.Context, request interface{}) (interface{}, error) {
			path := gc.FullPath()
			// skip public paths
			// TODO allow customize public paths
			if strings.HasSuffix(path, "/login") ||
				strings.HasSuffix(path, "/auth/refresh") {
				return nil, nil
			}
			var err error
			var token *jwtToken
			header := gc.GetHeader("Authorization")
			if "" == header { // process auth cookies
				if token, err = s.handleCookieAuth(gc); err != nil {
					return nil, err
				}
			} else { // process auth header
				parts := strings.Split(header, " ")
				if len(parts) != 2 { // invalid header
					gc.AbortWithStatus(http.StatusUnauthorized)
					return nil, ErrInvalidHeader
				}
				switch strings.ToLower(parts[0]) {
				case "bearer": // process access token
					if token, err = s.handleBearerAuth(
						gc, parts[1],
					); err != nil {
						gc.AbortWithStatus(http.StatusUnauthorized)
						return nil, err
					}
				case "token": // process personal (long-lived) token
					if token, err = s.handleTokenAuth(
						gc, parts[1],
					); err != nil {
						gc.AbortWithStatus(http.StatusUnauthorized)
						return nil, err
					}
				default: // invalid header
					gc.AbortWithStatus(http.StatusUnauthorized)
					return nil, ErrInvalidHeader
				}
			}
			if err = token.checkAccessToken(); err != nil {
				gc.AbortWithStatus(http.StatusUnauthorized)
				return nil, err
			}
			gc.Set(AccessTokenName, token)
			return nil, nil
		}
	}
}

func (s Server) handleCookieAuth(gc *gin.Context) (*jwtToken, error) {
	token, err := s.getAccessToken(gc)
	if err != nil {
		gc.AbortWithStatus(http.StatusUnauthorized)
		return nil, err
	}
	return token, err
}

func (s Server) handleBearerAuth(gc *gin.Context, token string) (
	*jwtToken, error,
) {
	t, err := s.jwtTokenFromString(gc, token)
	if err != nil {
		gc.AbortWithStatus(http.StatusUnauthorized)
		return nil, err
	}
	err = t.checkAccessToken()
	if err != nil {
		gc.AbortWithStatus(http.StatusUnauthorized)
		return nil, err
	}
	return t, nil
}

func (s Server) handleTokenAuth(gc *gin.Context, token string) (
	*jwtToken, error,
) {
	t, err := s.jwtTokenFromString(gc, token)
	if err != nil {
		gc.AbortWithStatus(http.StatusUnauthorized)
		return nil, err
	}
	err = t.checkPersonalToken()
	if err != nil {
		gc.AbortWithStatus(http.StatusUnauthorized)
		return nil, err
	}
	return t, nil
}
