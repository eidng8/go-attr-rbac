package api

import (
	"context"
	"net/http"

	"github.com/eidng8/go-utils"
	"github.com/gin-gonic/gin"
	"github.com/oapi-codegen/runtime/types"

	"github.com/eidng8/go-attr-rbac/ent"
	"github.com/eidng8/go-attr-rbac/ent/user"
)

// Login authenticates the user and sets the access and refresh token cookie.
//
// TODO login using personal token?
//
// Endpoint: POST /login
func (s Server) Login(
	ctx context.Context, req LoginRequestObject,
) (LoginResponseObject, error) {
	gc, ok := ctx.(*gin.Context)
	if !ok {
		return nil, errInvalidContext
	}

	// check user credentials
	qc := context.Background()
	u, err := s.db.User.Query().Where(user.UsernameEQ(req.Body.Username)).
		Only(qc)
	if err != nil {
		if ent.IsNotFound(err) {
			return Login401JSONResponse{
				N401JSONResponse: N401JSONResponse{
					Code:   http.StatusUnauthorized,
					Errors: &ResponseMessageCredentialNotFound,
					Status: http.StatusText(http.StatusUnauthorized),
				},
			}, nil
		}
		Log.Debugf("login failed: %v", err)
		return nil, err
	}
	m, e := utils.ComparePassword(req.Body.Password, u.Password)
	if e != nil {
		Log.Debugf("login failed: %v", e)
		return Login401JSONResponse{
			N401JSONResponse: N401JSONResponse{
				Code:   http.StatusUnauthorized,
				Errors: &ResponseMessageCredentialsInvalid,
				Status: msgError,
			},
		}, nil
	}
	if !m {
		return Login401JSONResponse{
			N401JSONResponse: N401JSONResponse{
				Code:   http.StatusUnauthorized,
				Errors: &ResponseMessageCredentialsInvalid,
				Status: msgError,
			},
		}, nil
	}

	// generate access token and refresh token
	at, err := s.issueAccessToken(u)
	if err != nil || "" == at {
		return nil, err
	}
	rt, err := s.issueRefreshToken(u)
	if err != nil || "" == rt {
		return nil, err
	}
	s.setToken(gc, at, rt)

	res := Login200JSONResponse{
		Id:        u.ID,
		Username:  u.Username,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
	if nil != u.Email && "" != *u.Email {
		email := types.Email(*u.Email)
		res.Email = &email
	}
	return res, nil
}