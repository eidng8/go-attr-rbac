package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oapi-codegen/runtime/types"
	"golang.org/x/crypto/bcrypt"

	"github.com/eidng8/go-attr-rbac/ent/user"
)

func (s Server) Login(
	ctx context.Context, request LoginRequestObject,
) (LoginResponseObject, error) {
	// check user credentials
	qc := context.Background()
	u, err := s.db.User.Query().Where(user.UsernameEQ(request.Body.Username)).
		Only(qc)
	if err != nil {
		return nil, err
	}
	err = bcrypt.CompareHashAndPassword(
		[]byte(u.Password), []byte(request.Body.Password),
	)
	if err != nil {
		return Login401Response{}, nil
	}
	email := types.Email(u.Email)

	// generate access token and refresh token
	at, err := s.issueAccessToken(u)
	if err != nil || "" == at {
		return nil, err
	}
	rt, err := s.issueRefreshToken(u)
	if err != nil || "" == rt {
		return nil, err
	}

	// set cookies
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, ErrInvalidContext
	}
	gc.SetSameSite(http.SameSiteStrictMode)
	s.setCookie(gc, AccessTokenName, at, "/", 3600)
	s.setCookie(gc, RefreshTokenName, rt, "/access-token", 7*24*3600)

	return Login200JSONResponse{
		Id:        u.ID,
		Username:  u.Username,
		Email:     &email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}, nil
}
