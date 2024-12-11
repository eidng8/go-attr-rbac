package handlers

import (
	"context"
	"slices"

	"github.com/eidng8/go-utils"
	"github.com/gin-gonic/gin"

	"github.com/eidng8/go-attr-rbac/api"
	"github.com/eidng8/go-attr-rbac/ent"
)

// CheckAccessToken checks whether current access token is valid.
//
// Endpoint: GET /access-token
func (s Server) CheckAccessToken(
	ctx context.Context, _ CheckAccessTokenRequestObject,
) (CheckAccessTokenResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}
	token, err := s.getToken(gc)
	if err != nil {
		api.Log.Debugf("check access token failed: %v", err)
		return CheckAccessToken401JSONResponse{}, nil
	}
	roles, err := token.getRoles()
	if err != nil {
		api.Log.Debugf("check access token failed: %v", err)
		return CheckAccessToken401JSONResponse{}, nil
	}
	r := utils.Pluck(token.user.Edges.Roles, ent.PluckRoleName)
	if slices.Equal(r, *roles) {
		return CheckAccessToken204Response{}, nil
	}
	return CheckAccessToken401JSONResponse{}, nil
}
